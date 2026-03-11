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
	"net/http"
	"crypto/tls"
	"log/slog"
	"os"
	"os/exec"
	"strings"
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
		msg := fmt.Sprintf("ObsidianWatch agent: config load failed: %v\nConfig path: %s\n", err, *cfgPath)
		fmt.Fprint(os.Stderr, msg)
		// When running as a Windows service stderr is invisible -- also write a
		// crash log beside the executable so the problem is diagnosable.
		if exeDir, e2 := filepath.Abs(filepath.Dir(os.Args[0])); e2 == nil {
			_ = os.WriteFile(filepath.Join(exeDir, "agent-error.log"),
				[]byte(msg), 0644)
		}
		os.Exit(1)
	}

	logger := buildLogger(cfg.Log.Level, cfg.Log.Format)

	if isService {
		// Running as a Windows service — hand control to the service manager.
		if err := svc.Run(serviceName, &agentService{cfg: cfg, cfgPath: *cfgPath, logger: logger}); err != nil {
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
	if err := run(ctx, cfg, *cfgPath, logger); err != nil {
		logger.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// agentService implements svc.Handler for the Windows service manager.
// ---------------------------------------------------------------------------

type agentService struct {
	cfg     *config.Config
	cfgPath string
	logger  *slog.Logger
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := run(ctx, s.cfg, s.cfgPath, s.logger); err != nil {
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

func run(ctx context.Context, cfg *config.Config, cfgPath string, logger *slog.Logger) error {
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
	// Resolve cert paths relative to the config file directory so that
	// relative paths like "certs/ca.crt" work when running as a Windows
	// service (which uses System32 as its working directory).
	cfgDir := filepath.Dir(cfgPath)
	resolveRelative := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(cfgDir, p)
	}
	fwdCfg := forwarder.ForwarderConfig{
		InstallKey:    cfg.Forwarder.InstallKey,
		BackendURL:    cfg.Forwarder.BackendURL,
		BatchSize:     cfg.Forwarder.BatchSize,
		FlushInterval: cfg.Forwarder.FlushInterval,
		CertFile:      resolveRelative(cfg.Forwarder.CertFile),
		KeyFile:       resolveRelative(cfg.Forwarder.KeyFile),
		CAFile:        resolveRelative(cfg.Forwarder.CAFile),
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

	// ── Location collector ───────────────────────────────────────────────
	// Uses Windows Location API (GPS → WiFi → IP fallback), posts to backend.
	{
		c := collector.NewLocationCollector(
			30*time.Minute,
			agentID, hostInfo.Hostname,
			cfg.Forwarder.BackendURL, cfg.Forwarder.APIKey,
			resolveRelative(cfg.Forwarder.CAFile),
			eventCh, // bypasses rate limiter — location is low frequency
			logger,
		)
		startCollector("location", c.Run)
		activeCollectors = append(activeCollectors, "location")
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
		return uninstallService(cfgPath)
	default:
		return fmt.Errorf("unknown command %q (valid: install, uninstall)", cmd)
	}
}

func installService(cfgPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}

	// Resolve both paths to absolute so the Windows SCM can find them.
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("abs exe path: %w", err)
	}
	cfgPath, err = filepath.Abs(cfgPath)
	if err != nil {
		return fmt.Errorf("abs config path: %w", err)
	}

	cfg, cfgErr := config.Load(cfgPath)
	if cfgErr != nil {
		return fmt.Errorf("load config: %w", cfgErr)
	}

	// ── Tamper Protection Password ──────────────────────────────────────────
	// The install password is chosen interactively at install time.
	// It is registered on the management server and shown on the dashboard.
	// The same password is required to uninstall the agent.
	fmt.Println("=======================================================")
	fmt.Println("  ObsidianWatch -- Tamper Protection Setup")
	fmt.Println("=======================================================")
	fmt.Println("  Choose a password that will be required to uninstall")
	fmt.Println("  this agent. Save it safely - it cannot be recovered.")
	fmt.Println("  It will appear on the ObsidianWatch dashboard.")
	fmt.Println("=======================================================")
	fmt.Print("  Enter tamper protection password: ")

	var installPassword string
	fmt.Scanln(&installPassword)
	installPassword = strings.TrimSpace(installPassword)

	if installPassword == "" {
		return fmt.Errorf("install cancelled: no password provided")
	}
	if len(installPassword) < 8 {
		return fmt.Errorf("install cancelled: password must be at least 8 characters")
	}

	// Determine agent ID (same logic as run() — hostname by default)
	agentInstallID := cfg.Agent.ID
	if agentInstallID == "" {
		if h, err2 := os.Hostname(); err2 == nil {
			agentInstallID = h
		}
	}

	// Register password with management server so it appears on dashboard.
	if cfg.Forwarder.ManagementURL != "" {
		fmt.Println("  Registering password with management server...")
		if err := registerInstallKey(cfg.Forwarder.ManagementURL, cfg.Forwarder.APIKey, agentInstallID, installPassword); err != nil {
			fmt.Printf("  Warning: could not register with server: %v\n", err)
			fmt.Println("  The key will be saved locally and synced on first connection.")
		} else {
			fmt.Println("  Password registered on dashboard OK.")
		}
	}

	// Patch only the install_key line in the yaml — never rewrite the whole
	// config or duration fields (5s) get mangled to nanoseconds (5000000000).
	if err := config.SaveInstallKey(cfgPath, installPassword); err != nil {
		fmt.Printf("  Warning: could not save key to config: %v\n", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	defer m.Disconnect()

	// If service already exists, remove it first using raw Win32.
	// mgr.OpenService uses SERVICE_ALL_ACCESS which is denied by a prior tamper DACL,
	// so we open with WRITE_DAC + WRITE_OWNER to reset security first, then delete.
	removeExistingService(serviceName)

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
	}, "-config", cfgPath)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	// Apply tamper-protection DACL: deny SERVICE_STOP and DELETE for everyone
	// except SYSTEM and our own service account. This prevents even local
	// admins from stopping/uninstalling the service without the key.
	if err := applyTamperDACL(s); err != nil {
		// Non-fatal: log warning but continue
		fmt.Printf("Warning: could not apply tamper DACL: %v\n", err)
	}

	fmt.Printf("Service %q installed with tamper protection.\n", serviceName)

	// Start the service immediately so it shows online on the dashboard right away.
	fmt.Println("Starting service...")
	if err := s.Start(); err != nil {
		fmt.Printf("Warning: service installed but could not auto-start: %v\n", err)
		fmt.Println("Start it manually: Start-Service ObsidianWatchAgent")
	} else {
		fmt.Println("Service started. Agent should appear online on the dashboard within seconds.")
	}
	return nil
}

// enablePrivilege enables a named privilege in the current process token.
// Required before SetServiceObjectSecurity with DACL/OWNER flags.
func enablePrivilege(name string) {
	var token windows.Token
	proc, _ := windows.GetCurrentProcess()
	_ = windows.OpenProcessToken(proc, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	defer token.Close()
	var luid windows.LUID
	namep, _ := windows.UTF16PtrFromString(name)
	advapi32p := windows.NewLazySystemDLL("advapi32.dll")
	lookupPriv := advapi32p.NewProc("LookupPrivilegeValueW")
	lookupPriv.Call(0, uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(&luid)))
	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
}

// deleteServiceViaSYSTEM is the last-resort fallback when WRITE_DAC is blocked.
// Creates a one-shot scheduled task running as SYSTEM that resets the DACL,
// stops, and deletes the service — SYSTEM bypasses all DACLs.
func deleteServiceViaSYSTEM(svcName string) error {
	fmt.Println("  Direct DACL unlock blocked — spawning SYSTEM task as fallback...")
	taskName := "OW_Uninstall_" + svcName
	script := fmt.Sprintf(
		`sc.exe sdset %s D:(A;;RPWPDTLOCRSDRCWDWO;;;SY)(A;;RPWPDTLOCRSDRCWDWO;;;BA) & sc.exe stop %s & timeout /t 3 & sc.exe delete %s`,
		svcName, svcName, svcName)
	// Create the task
	create := exec.Command("schtasks.exe", "/Create", "/F",
		"/SC", "ONCE", "/ST", "00:00",
		"/TN", taskName,
		"/TR", `cmd.exe /c `+script,
		"/RU", "SYSTEM", "/RL", "HIGHEST")
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("create task failed: %v: %s", err, out)
	}
	// Run immediately
	exec.Command("schtasks.exe", "/Run", "/TN", taskName).Run()
	fmt.Println("  Waiting for SYSTEM task to complete...")
	time.Sleep(8 * time.Second)
	// Cleanup
	exec.Command("schtasks.exe", "/Delete", "/F", "/TN", taskName).Run()
	fmt.Println("  Service removed via SYSTEM task.")
	return nil
}

// removeExistingService removes a previous installation using raw Win32 calls
// so it works even when the service has a tamper-protection DACL that blocks
// the high-level mgr.OpenService (which requests SERVICE_ALL_ACCESS).
func removeExistingService(name string) {
	const (
		SC_MANAGER_CONNECT    = 0x0001
		SERVICE_WRITE_DAC     = 0x00040000
		SERVICE_ALL_ACCESS    = 0x000F01FF
	)
	advapi32r := windows.NewLazySystemDLL("advapi32.dll")
	openSCMr   := advapi32r.NewProc("OpenSCManagerW")
	openSvcR   := advapi32r.NewProc("OpenServiceW")
	closeHndR  := advapi32r.NewProc("CloseServiceHandle")
	setSecR    := advapi32r.NewProc("SetServiceObjectSecurity")
	controlR   := advapi32r.NewProc("ControlService")
	deleteR    := advapi32r.NewProc("DeleteService")

	scmName, _ := windows.UTF16PtrFromString("")
	scmDB, _   := windows.UTF16PtrFromString("ServicesActive")
	scm, _, _  := openSCMr.Call(
		uintptr(unsafe.Pointer(scmName)),
		uintptr(unsafe.Pointer(scmDB)),
		SC_MANAGER_CONNECT,
	)
	if scm == 0 { return }
	defer closeHndR.Call(scm)

	svcName, _ := windows.UTF16PtrFromString(name)

	// First open with WRITE_DAC to reset DACL
	hDac, _, _ := openSvcR.Call(scm, uintptr(unsafe.Pointer(svcName)), SERVICE_WRITE_DAC)
	if hDac == 0 { return } // service doesn't exist — nothing to remove

	unlockSddl := "D:P(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"
	if sd, err := windows.SecurityDescriptorFromString(unlockSddl); err == nil {
		setSecR.Call(hDac, 4, uintptr(unsafe.Pointer(sd)))
	}
	closeHndR.Call(hDac)

	// Now open with full access to stop and delete
	hFull, _, _ := openSvcR.Call(scm, uintptr(unsafe.Pointer(svcName)), SERVICE_ALL_ACCESS)
	if hFull == 0 { return }

	var status windows.SERVICE_STATUS
	controlR.Call(hFull, windows.SERVICE_CONTROL_STOP, uintptr(unsafe.Pointer(&status)))
	time.Sleep(2 * time.Second)
	deleteR.Call(hFull)
	closeHndR.Call(hFull)
	time.Sleep(1 * time.Second)
	fmt.Println("  Removed existing service installation.")
}

// applyTamperDACL sets a restrictive security descriptor on the service that
// prevents stop/delete by non-SYSTEM accounts.
//
// Service-specific hex rights used in SDDL:
//   0x000F01FF = SERVICE_ALL_ACCESS  (SYSTEM gets everything)
//   0x0002019D = query/start/pause/read but NOT stop/delete (Administrators)
//   0x00010020 = SERVICE_STOP | DELETE  (denied for Everyone)
func applyTamperDACL(s *mgr.Service) error {
	// Hex masks avoid the invalid generic-rights keywords that caused parse errors.
	sddl := "D:P(A;;0x000F01FF;;;SY)(A;;0x0002019D;;;BA)(D;;0x00010020;;;WD)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL: %w", err)
	}
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	setSec := advapi32.NewProc("SetServiceObjectSecurity")
	// DACL_SECURITY_INFORMATION = 0x4
	ret, _, err2 := setSec.Call(uintptr(s.Handle), 4, uintptr(unsafe.Pointer(sd)))
	if ret == 0 {
		return fmt.Errorf("SetServiceObjectSecurity: %w", err2)
	}
	return nil
}

// registerInstallKey registers a chosen password as the agent's install key
// on the management server. The key is stored in the DB and shown on the dashboard.
func registerInstallKey(mgmtURL, apiKey, agentID, password string) error {
	mgmtURL = strings.TrimRight(mgmtURL, "/")
	body := fmt.Sprintf(`{"agent_id":%q,"install_key":%q}`, agentID, password)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequest(http.MethodPost, mgmtURL+"/api/v1/agent/register-key",
		strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// verifyInstallKey checks the key against the management server.
func verifyInstallKey(key, mgmtURL string) bool {
	// mgmtURL is the management platform e.g. http://192.168.1.140
	// (NOT the agent backend port 8443)
	if mgmtURL == "" {
		fmt.Println("Warning: management_url not set in config -- cannot verify install key")
		return false
	}
	// Strip trailing slash
	mgmtURL = strings.TrimRight(mgmtURL, "/")
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(mgmtURL + "/api/v1/verify-install-key?key=" + key)
	if err != nil {
		fmt.Printf("Warning: could not reach management server at %s: %v\n", mgmtURL, err)
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func uninstallService(cfgPath string) error {
	// Always prompt interactively for the install key -- even if it's in the
	// config file. This ensures a human must consciously provide the key to
	// uninstall. Someone who just has the config file cannot silently remove
	// the agent.
	cfg, cfgErr := config.Load(cfgPath)
	mgmtURL := ""
	if cfgErr == nil {
		mgmtURL = cfg.Forwarder.ManagementURL
	}

	fmt.Println("=======================================================")
	fmt.Println("  ObsidianWatch -- Tamper Protection")
	fmt.Println("=======================================================")
	fmt.Println("  To uninstall, enter the Install Key shown on the")
	fmt.Println("  ObsidianWatch dashboard:")
	fmt.Println("    Agents -> shield icon -> Install Key")
	fmt.Println("=======================================================")
	fmt.Print("  Enter Install Key: ")

	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)

	if input == "" {
		return fmt.Errorf("uninstall cancelled: no key provided")
	}

	if mgmtURL == "" {
		// No management URL -- accept key without server verification
		// (offline mode, key is checked locally against config)
		if cfgErr == nil && cfg.Forwarder.InstallKey != "" && input != cfg.Forwarder.InstallKey {
			return fmt.Errorf("tamper protection: invalid install key")
		}
		fmt.Println("  Key accepted (offline). Proceeding with uninstall.")
	} else {
		fmt.Println("  Verifying key against management server...")
		if !verifyInstallKey(input, mgmtURL) {
			return fmt.Errorf("tamper protection: invalid install key -- check the ObsidianWatch dashboard")
		}
		fmt.Println("  Key verified OK. Proceeding with uninstall.")
	}

	// ── Raw Win32 uninstall with DACL bypass ────────────────────────────────
	// Our tamper DACL denies SERVICE_STOP and DELETE for everyone except SYSTEM.
	// mgr.OpenService requests SERVICE_ALL_ACCESS which includes those rights
	// and gets Access Denied before we can even unlock the DACL.
	//
	// Fix: open the service with only WRITE_DAC (0x00040000) which IS allowed
	// by our DACL, reset the security descriptor to allow full admin access,
	// then stop and delete using a fresh handle with full rights.

	const (
		SC_MANAGER_CONNECT = 0x0001         // always granted to any user
		SERVICE_WRITE_DAC  = 0x00040000     // not in our deny list — should be allowed
		SERVICE_ALL_ACCESS = 0x000F01FF
	)

	// Enable SE_TAKE_OWNERSHIP_NAME so we can take ownership of the service
	// object and then reset its DACL regardless of existing restrictions.
	enablePrivilege("SeTakeOwnershipPrivilege")
	enablePrivilege("SeSecurityPrivilege")

	advapi32u := windows.NewLazySystemDLL("advapi32.dll")
	openSCM   := advapi32u.NewProc("OpenSCManagerW")
	openSvc   := advapi32u.NewProc("OpenServiceW")
	closeHnd  := advapi32u.NewProc("CloseServiceHandle")
	setSec2   := advapi32u.NewProc("SetServiceObjectSecurity")

	// Open SCM with CONNECT only — always succeeds for any local user
	scmName, _ := windows.UTF16PtrFromString("")
	scmDB, _   := windows.UTF16PtrFromString("ServicesActive")
	scmHandle, _, _ := openSCM.Call(
		uintptr(unsafe.Pointer(scmName)),
		uintptr(unsafe.Pointer(scmDB)),
		SC_MANAGER_CONNECT,
	)
	if scmHandle == 0 {
		return fmt.Errorf("OpenSCManager failed: %w", windows.GetLastError())
	}
	defer closeHnd.Call(scmHandle)

	svcName, _ := windows.UTF16PtrFromString(serviceName)

	// Step 1: Open with WRITE_DAC|WRITE_OWNER — our deny ACE only blocks
	// SERVICE_STOP (0x20) and DELETE (0x10000), not DAC/owner writes.
	hDac, _, _ := openSvc.Call(scmHandle, uintptr(unsafe.Pointer(svcName)), SERVICE_WRITE_DAC)
	if hDac == 0 {
		// Last resort: use a scheduled task running as SYSTEM to delete
		return deleteServiceViaSYSTEM(serviceName)
	}

	// Step 2: Reset DACL to allow admins full access
	unlockSddl := "D:P(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(unlockSddl)
	if err != nil {
		closeHnd.Call(hDac)
		return fmt.Errorf("build unlock SDDL: %w", err)
	}
	ret, _, _ := setSec2.Call(hDac, 4, uintptr(unsafe.Pointer(sd))) // DACL_SECURITY_INFORMATION = 4
	closeHnd.Call(hDac)
	if ret == 0 {
		fmt.Printf("Warning: could not unlock DACL (err=%v) — trying anyway\n", windows.GetLastError())
	} else {
		fmt.Println("  DACL unlocked. Service can now be stopped and removed.")
	}

	// Step 3: Open with STOP + ALL_ACCESS to stop and delete
	hFull, _, _ := openSvc.Call(scmHandle, uintptr(unsafe.Pointer(svcName)), SERVICE_ALL_ACCESS)
	if hFull == 0 {
		return fmt.Errorf("OpenService (full access) failed after DACL unlock: %w", windows.GetLastError())
	}

	// Stop the service if running
	var svcStatus windows.SERVICE_STATUS
	controlSvc := advapi32u.NewProc("ControlService")
	querySvc   := advapi32u.NewProc("QueryServiceStatus")
	querySvc.Call(hFull, uintptr(unsafe.Pointer(&svcStatus)))
	if svcStatus.CurrentState != windows.SERVICE_STOPPED {
		controlSvc.Call(hFull, windows.SERVICE_CONTROL_STOP, uintptr(unsafe.Pointer(&svcStatus)))
		fmt.Println("  Stop signal sent. Waiting...")
		time.Sleep(3 * time.Second)
	}

	// Delete the service
	deleteSvc := advapi32u.NewProc("DeleteService")
	ret2, _, errDel := deleteSvc.Call(hFull)
	closeHnd.Call(hFull)
	if ret2 == 0 {
		return fmt.Errorf("DeleteService failed: %w", errDel)
	}

	fmt.Println("  Service uninstalled successfully.")
	fmt.Println("  The agent will stop sending events. The tamper password is no longer needed.")
	return nil
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
	regSetValueEx  := modAdvapi32Reg.NewProc("RegSetValueExW")
	regCreateKeyEx := modAdvapi32Reg.NewProc("RegCreateKeyExW")
	regCloseKey    := modAdvapi32Reg.NewProc("RegCloseKey")

	setDWORD := func(hive windows.Handle, path, name string, val uint32) error {
		keyPtr, _ := windows.UTF16PtrFromString(path)
		namePtr, _ := windows.UTF16PtrFromString(name)
		const KEY_SET_VALUE  = 0x0002
		const KEY_WOW64_64KEY = 0x0100
		const REG_OPTION_NON_VOLATILE = 0x00000000
		var hkey windows.Handle
		var disposition uint32
		// RegCreateKeyEx creates the key AND all intermediate keys if they don't exist
		ret, _, _ := regCreateKeyEx.Call(
			uintptr(hive), uintptr(unsafe.Pointer(keyPtr)),
			0, 0, REG_OPTION_NON_VOLATILE,
			KEY_SET_VALUE|KEY_WOW64_64KEY,
			0,
			uintptr(unsafe.Pointer(&hkey)),
			uintptr(unsafe.Pointer(&disposition)),
		)
		if ret != 0 {
			return fmt.Errorf("RegCreateKeyEx: %d", ret)
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
