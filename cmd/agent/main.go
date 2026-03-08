// obsidianwatch-agent — Windows security event collection agent.
//
// Usage:
//   agent.exe -config agent.yaml          # run interactively
//   agent.exe -config agent.yaml install  # install as Windows service
//   agent.exe uninstall                   # remove service
//   agent.exe start | stop | status       # service control

//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"obsidianwatch/agent/internal/collector"
	"obsidianwatch/agent/internal/config"
	"obsidianwatch/agent/internal/forwarder"
	"obsidianwatch/agent/internal/parser"
	sysmonpkg "obsidianwatch/agent/internal/sysmon"
	"obsidianwatch/agent/pkg/schema"
)

const (
	serviceName        = "ObsidianWatchAgent"
	serviceDisplayName = "ObsidianWatch Security Agent"
	serviceDescription = "Collects Windows security events and forwards them to the ObsidianWatch backend."
)

func main() {
	cfgPath := flag.String("config", "agent.yaml", "path to agent config file")
	flag.Parse()

	// Determine if we are running as a Windows service or interactively.
	// IsWindowsService returns true when running under the SCM.
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svc.IsWindowsService: %v\n", err)
		os.Exit(1)
	}

	// Handle install / uninstall verbs — always in interactive context.
	if flag.NArg() > 0 {
		if err := handleCommand(flag.Arg(0), *cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load: %v\n", err)
		os.Exit(1)
	}

	logger := buildLogger(cfg.Log.Level, cfg.Log.Format)

	if isService {
		// Running as a Windows service — hand control to the service manager.
		if err := svc.Run(serviceName, &agentService{cfg: cfg, logger: logger}); err != nil {
			logger.Error("service run failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// Enable Windows audit policies for full command line visibility
	enableAuditPolicies(logger)

	// Interactive mode — run until SIGINT/SIGTERM.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("obsidianwatch-agent starting (interactive)", "version", cfg.Agent.Version)
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// agentService implements svc.Handler for the Windows service manager.
// ---------------------------------------------------------------------------

type agentService struct {
	cfg    *config.Config
	logger *slog.Logger
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := run(ctx, s.cfg, s.logger); err != nil {
			s.logger.Error("agent run error", "err", err)
		}
	}()

	status <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			// Give collectors up to 10 s to flush.
			time.Sleep(10 * time.Second)
			return false, 0
		}
	}

	cancel()
	return false, 0
}

// ---------------------------------------------------------------------------
// run wires up all subsystems and runs until ctx is cancelled.
// ---------------------------------------------------------------------------

func run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	// Ensure required directories exist before any subsystem tries to use them.
	// This means the user never has to create folders manually.
	dirsToCreate := []string{
		`C:\Program Files\ObsidianWatch\Agent\certs`,
		`C:\ProgramData\ObsidianWatch`,
	}
	if cfg.Queue.DBPath != "" {
		dirsToCreate = append(dirsToCreate, filepath.Dir(cfg.Queue.DBPath))
	}
	for _, d := range dirsToCreate {
		if err := os.MkdirAll(d, 0755); err != nil {
			logger.Warn("could not create directory", "path", d, "err", err)
		}
	}

	// Ensure required Windows services are running before starting collectors.
	ensureWindowsServices(logger)

	// Resolve host metadata once.
	agentID := cfg.Agent.ID
	if agentID == "" {
		h, _ := os.Hostname()
		agentID = h
	}
	hostInfo := parser.ResolveHostInfo(agentID, cfg.Agent.Version)

	// Pipeline channel: collectors → normaliser/enricher → forwarder
	eventCh := make(chan schema.Event, 4096)

	// --- Queue (offline buffer) ---
	q, err := forwarder.NewQueue(cfg.Queue.DBPath, cfg.Queue.MaxRows, logger)
	if err != nil {
		return fmt.Errorf("queue init: %w", err)
	}
	defer q.Close()

	// --- Forwarder ---
	fwdCfg := forwarder.ForwarderConfig{
		BackendURL:    cfg.Forwarder.BackendURL,
		BatchSize:     cfg.Forwarder.BatchSize,
		FlushInterval: cfg.Forwarder.FlushInterval,
		CertFile:      cfg.Forwarder.CertFile,
		KeyFile:       cfg.Forwarder.KeyFile,
		CAFile:        cfg.Forwarder.CAFile,
		APIKey:        cfg.Forwarder.APIKey,
	}
	fwd, err := forwarder.NewHTTPForwarder(fwdCfg, q, agentID, cfg.Agent.Version, logger)
	if err != nil {
		return fmt.Errorf("forwarder init: %w", err)
	}

	// --- Normaliser + Enricher ---
	norm := parser.NewNormalizer(logger)
	enrch := parser.NewEnricher(hostInfo, logger)

	// Dispatcher goroutine: reads from eventCh, normalises, enriches, enqueues.
	go func() {
		buf := make([]schema.Event, 0, cfg.Forwarder.BatchSize)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			buf = norm.NormalizeBatch(buf)
			enrch.EnrichBatch(buf)
			fwd.Enqueue(buf)
			buf = buf[:0]
		}
		ticker := time.NewTicker(cfg.Forwarder.FlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case ev := <-eventCh:
				buf = append(buf, ev)
				if len(buf) >= cfg.Forwarder.BatchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	// --- Collectors ---
	errCh := make(chan error, 8)

	startCollector := func(name string, fn func(context.Context) error) {
		go func() {
			logger.Info("collector: starting", "name", name)
			if err := fn(ctx); err != nil {
				logger.Error("collector: error", "name", name, "err", err)
				errCh <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}

	// ── Rate limiter ─────────────────────────────────────────────────────
	// Sits between collectors and the dispatcher — wraps eventCh.
	var dispatchCh chan schema.Event
	if cfg.Collector.RateLimit.Enabled {
		rawCh := make(chan schema.Event, 4096)
		dispatchCh = rawCh
		// Replace eventCh with rawCh for all collectors below.
		// The rate limiter will forward allowed events into the original eventCh.
		rlCfg := collector.RateLimitConfig{
			MaxPerSecond: cfg.Collector.RateLimit.MaxPerSecond,
			DedupeWindow: cfg.Collector.RateLimit.DedupeWindow,
		}
		limiter := collector.NewRateLimiter(rlCfg)
		go collector.FilteredChannel(rawCh, eventCh, limiter)
		logger.Info("ratelimit: enabled", "max_per_sec", rlCfg.MaxPerSecond, "dedupe_window", rlCfg.DedupeWindow)
	} else {
		dispatchCh = eventCh
	}

	// Track active collector names for health reporting
	activeCollectors := []string{}

	if cfg.Collector.EventLog.Enabled {
		c := collector.NewEventLogCollector(
			cfg.Collector.EventLog.Channels,
			agentID, hostInfo.Hostname, dispatchCh, logger,
		)
		startCollector("eventlog", c.Run)
		activeCollectors = append(activeCollectors, "eventlog")
	}

	if cfg.Collector.Sysmon.Enabled {
		c := collector.NewSysmonCollector(agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("sysmon", c.Run)
		activeCollectors = append(activeCollectors, "sysmon")
	}

	if cfg.Collector.Network.Enabled {
		c := collector.NewNetworkCollector(
			cfg.Collector.Network.PollInterval,
			agentID, hostInfo.Hostname, dispatchCh, logger,
		)
		startCollector("network", c.Run)
		activeCollectors = append(activeCollectors, "network")
	}

	if cfg.Collector.Process.Enabled {
		c := collector.NewProcessCollector(agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("process", c.Run)
		activeCollectors = append(activeCollectors, "process")
	}

	if cfg.Collector.Registry.Enabled {
		c := collector.NewRegistryCollector(
			cfg.Collector.Registry.Keys,
			agentID, hostInfo.Hostname, dispatchCh, logger,
		)
		startCollector("registry", c.Run)
		activeCollectors = append(activeCollectors, "registry")
	}

	if cfg.Collector.DNS.Enabled {
		c := collector.NewDNSCollector(agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("dns", c.Run)
		activeCollectors = append(activeCollectors, "dns")
	}

	if cfg.Collector.FIM.Enabled && len(cfg.Collector.FIM.Dirs) > 0 {
		fimDirs := make([]collector.FIMConfig, len(cfg.Collector.FIM.Dirs))
		for i, d := range cfg.Collector.FIM.Dirs {
			fimDirs[i] = collector.FIMConfig{
				Path:      d.Path,
				Recursive: d.Recursive,
				Exclude:   d.Exclude,
			}
		}
		c := collector.NewFIMCollector(fimDirs, agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("fim", c.Run)
		activeCollectors = append(activeCollectors, "fim")
	}

	if len(cfg.Collector.AppLogs) > 0 {
		stateDir := filepath.Join(filepath.Dir(cfg.Queue.DBPath), "applog_state")
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			logger.Warn("applog: could not create state dir", "dir", stateDir, "err", err)
		}
		appCfgs := make([]collector.AppLogConfig, len(cfg.Collector.AppLogs))
		for i, a := range cfg.Collector.AppLogs {
			appCfgs[i] = collector.AppLogConfig{
				Name:      a.Name,
				Path:      a.Path,
				Format:    a.Format,
				EventType: a.EventType,
				Severity:  a.Severity,
			}
		}
		c := collector.NewAppLogCollector(appCfgs, stateDir, agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("applog", c.Run)
		activeCollectors = append(activeCollectors, "applog")
		logger.Info("applog: collector started", "files", len(appCfgs))
	}

	if cfg.Collector.Health.Enabled {
		c := collector.NewHealthReporter(
			cfg.Collector.Health.Interval,
			agentID, hostInfo.Hostname, cfg.Agent.Version,
			activeCollectors,
			eventCh, // health bypasses rate limiter — always send
			logger,
		)
		startCollector("health", c.Run)
	}

	// Start the HTTP forwarder (reads from queue, not eventCh).
	go func() { errCh <- fwd.Run(ctx) }()

	<-ctx.Done()
	logger.Info("agent shutting down")
	return nil
}

// ---------------------------------------------------------------------------
// Windows service management verbs
// ---------------------------------------------------------------------------

func handleCommand(cmd, cfgPath string) error {
	switch cmd {
	case "install":
		return installService(cfgPath)
	case "uninstall":
		return uninstallService()
	default:
		return fmt.Errorf("unknown command %q (valid: install, uninstall)", cmd)
	}
}

func installService(cfgPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
	}, "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	fmt.Printf("Service %q installed successfully.\n", serviceName)
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	return s.Delete()
}

// ---------------------------------------------------------------------------
// Windows service preflight
// ---------------------------------------------------------------------------

// ensureWindowsServices checks that services required for event collection
// are running. If a service is disabled it re-enables it first, then starts it.
func ensureWindowsServices(logger *slog.Logger) {
	// EventLog is required for EvtSubscribe to work.
	// WinRM is needed for RPC-based event log access.
	required := []string{"EventLog", "WinRM"}

	m, err := mgr.Connect()
	if err != nil {
		logger.Warn("preflight: cannot connect to service manager", "err", err)
		return
	}
	defer m.Disconnect()

	for _, name := range required {
		s, err := m.OpenService(name)
		if err != nil {
			logger.Warn("preflight: cannot open service", "service", name, "err", err)
			continue
		}

		status, err := s.Query()
		if err != nil {
			logger.Warn("preflight: cannot query service", "service", name, "err", err)
			s.Close()
			continue
		}

		if status.State == svc.Running {
			logger.Info("preflight: service already running", "service", name)
			s.Close()
			continue
		}

		// Check if the service is disabled — if so, re-enable it first.
		cfgSvc, err := s.Config()
		if err == nil && cfgSvc.StartType == mgr.StartDisabled {
			logger.Info("preflight: service is disabled, re-enabling", "service", name)
			cfgSvc.StartType = mgr.StartAutomatic
			if err := s.UpdateConfig(cfgSvc); err != nil {
				logger.Warn("preflight: failed to re-enable service", "service", name, "err", err)
				s.Close()
				continue
			}
			logger.Info("preflight: service re-enabled", "service", name)
		}

		// Now start the service.
		logger.Info("preflight: starting service", "service", name)
		if err := s.Start(); err != nil {
			logger.Warn("preflight: failed to start service", "service", name, "err", err)
			s.Close()
			continue
		}

		// Wait up to 15 seconds for the service to reach Running state.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
			if status.State == svc.Running {
				logger.Info("preflight: service started successfully", "service", name)
				break
			}
		}
		if status.State != svc.Running {
			logger.Warn("preflight: service did not reach running state", "service", name)
		}
		s.Close()
	}

	// Sysmon — auto-install if not present.
	// If not already admin, attempt to self-elevate via ShellExecute runas.
	switch sysmonpkg.Check() {
	case sysmonpkg.StatusRunning:
		logger.Info("preflight: Sysmon is running ✓")
	case sysmonpkg.StatusInstalled:
		if sysmonpkg.IsAdmin() {
			sysmonpkg.EnsureInstalled(logger)
		} else {
			logger.Warn("preflight: Sysmon installed but not running — attempting to start via elevation")
			if err := elevatedSysmonSetup(logger); err != nil {
				logger.Warn("preflight: elevation failed — start agent as Administrator", "err", err)
			}
		}
	case sysmonpkg.StatusNotInstalled:
		if sysmonpkg.IsAdmin() {
			logger.Info("preflight: Sysmon not installed — auto-installing now")
			sysmonpkg.EnsureInstalled(logger)
		} else {
			logger.Warn("preflight: Sysmon not installed — requesting elevation to install")
			if err := elevatedSysmonSetup(logger); err != nil {
				logger.Warn("preflight: could not auto-install Sysmon (run agent as Administrator for auto-install)", "err", err)
			}
		}
	}
}

// elevatedSysmonSetup re-launches this same agent.exe with runas (UAC prompt)
// just to perform the Sysmon install/start, then returns.
// The current (non-elevated) agent continues running normally after this.
func elevatedSysmonSetup(logger *slog.Logger) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	// ShellExecute with "runas" verb triggers UAC prompt
	modShell32    := windows.NewLazySystemDLL("shell32.dll")
	shellExecuteW := modShell32.NewProc("ShellExecuteW")

	operation, _ := windows.UTF16PtrFromString("runas")
	file, _      := windows.UTF16PtrFromString(exePath)
	params, _    := windows.UTF16PtrFromString("--sysmon-setup-only")
	dir, _       := windows.UTF16PtrFromString(filepath.Dir(exePath))

	const SW_HIDE = 0
	ret, _, err := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(operation)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		SW_HIDE,
	)
	// ShellExecute returns >32 on success
	if ret <= 32 {
		return fmt.Errorf("ShellExecuteW runas: %d %w", ret, err)
	}

	logger.Info("preflight: UAC elevation launched for Sysmon setup — accept the prompt to install Sysmon")
	// Give the elevated process time to complete install before we continue
	time.Sleep(15 * time.Second)

	// Check if it worked
	if sysmonpkg.Check() == sysmonpkg.StatusRunning {
		logger.Info("preflight: Sysmon auto-install succeeded via elevation ✓")
		return nil
	}
	return fmt.Errorf("Sysmon still not running after elevated setup attempt")
}

// ---------------------------------------------------------------------------
// Audit policy enablement
// ---------------------------------------------------------------------------

// enableAuditPolicies ensures Windows is configured to emit the event IDs
// that ObsidianWatch relies on — specifically:
//   - Event 4688 with command line (process creation with full cmdline)
//   - PowerShell Script Block Logging (4104)
//   - PowerShell Module Logging (4103)
//
// These settings are written to the registry and take effect immediately.
// Requires administrator privileges — silently skips on failure.
func enableAuditPolicies(logger *slog.Logger) {
	modAdvapi32Reg := windows.NewLazySystemDLL("advapi32.dll")
	regSetValueEx := modAdvapi32Reg.NewProc("RegSetValueExW")
	regOpenKeyEx  := modAdvapi32Reg.NewProc("RegOpenKeyExW")
	regCloseKey   := modAdvapi32Reg.NewProc("RegCloseKey")

	setDWORD := func(hive windows.Handle, path, name string, val uint32) error {
		keyPtr, _ := windows.UTF16PtrFromString(path)
		namePtr, _ := windows.UTF16PtrFromString(name)
		const KEY_SET_VALUE = 0x0002
		const KEY_WOW64_64KEY = 0x0100
		var hkey windows.Handle
		ret, _, _ := regOpenKeyEx.Call(
			uintptr(hive), uintptr(unsafe.Pointer(keyPtr)),
			0, KEY_SET_VALUE|KEY_WOW64_64KEY,
			uintptr(unsafe.Pointer(&hkey)),
		)
		if ret != 0 {
			return fmt.Errorf("RegOpenKeyEx: %d", ret)
		}
		defer regCloseKey.Call(uintptr(hkey))
		ret, _, _ = regSetValueEx.Call(
			uintptr(hkey), uintptr(unsafe.Pointer(namePtr)),
			0, 4, // REG_DWORD
			uintptr(unsafe.Pointer(&val)),
			4,
		)
		if ret != 0 {
			return fmt.Errorf("RegSetValueEx: %d", ret)
		}
		return nil
	}

	// 1. Enable Process Creation auditing with command line inclusion (Event 4688 + cmdline)
	//    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
	//    ProcessCreationIncludeCmdLine_Enabled = 1
	if err := setDWORD(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`,
		"ProcessCreationIncludeCmdLine_Enabled", 1); err != nil {
		logger.Warn("preflight: could not enable 4688 command line logging (need admin)", "err", err)
	} else {
		logger.Info("preflight: enabled Event 4688 command line inclusion")
	}

	// 2. Enable PowerShell Script Block Logging (Event 4104 — captures ACTUAL script text)
	//    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
	//    EnableScriptBlockLogging = 1
	if err := setDWORD(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
		"EnableScriptBlockLogging", 1); err != nil {
		logger.Warn("preflight: could not enable PowerShell Script Block Logging", "err", err)
	} else {
		logger.Info("preflight: enabled PowerShell Script Block Logging (Event 4104)")
	}

	// 3. Enable PowerShell Module Logging (Event 4103 — pipeline execution details)
	//    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
	//    EnableModuleLogging = 1
	if err := setDWORD(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`,
		"EnableModuleLogging", 1); err != nil {
		logger.Warn("preflight: could not enable PowerShell Module Logging", "err", err)
	} else {
		logger.Info("preflight: enabled PowerShell Module Logging (Event 4103)")
	}
}

// ---------------------------------------------------------------------------
// Logger factory
// ---------------------------------------------------------------------------

func buildLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}
