// opensiem-agent — Windows security event collection agent.
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
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"opensiem/agent/internal/collector"
	"opensiem/agent/internal/config"
	"opensiem/agent/internal/forwarder"
	"opensiem/agent/internal/parser"
	"opensiem/agent/pkg/schema"
)

const (
	serviceName        = "OpenSIEMAgent"
	serviceDisplayName = "OpenSIEM Security Agent"
	serviceDescription = "Collects Windows security events and forwards them to the OpenSIEM backend."
)

func main() {
	cfgPath := flag.String("config", "agent.yaml", "path to agent config file")
	flag.Parse()

	// Determine if we are running as an interactive process or a Windows service.
	interactive, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svc.IsWindowsService: %v\n", err)
		os.Exit(1)
	}

	// Handle install / uninstall / start / stop verbs.
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

	if !interactive {
		// Running as a Windows service — hand control to the service manager.
		if err := svc.Run(serviceName, &agentService{cfg: cfg, logger: logger}); err != nil {
			logger.Error("service run failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// Interactive mode — run until SIGINT/SIGTERM.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("opensiem-agent starting (interactive)", "version", cfg.Agent.Version)
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

	if cfg.Collector.EventLog.Enabled {
		c := collector.NewEventLogCollector(
			cfg.Collector.EventLog.Channels,
			agentID, hostInfo.Hostname, eventCh, logger,
		)
		startCollector("eventlog", c.Run)
	}

	if cfg.Collector.Sysmon.Enabled {
		c := collector.NewSysmonCollector(agentID, hostInfo.Hostname, eventCh, logger)
		startCollector("sysmon", c.Run)
	}

	if cfg.Collector.Network.Enabled {
		c := collector.NewNetworkCollector(
			cfg.Collector.Network.PollInterval,
			agentID, hostInfo.Hostname, eventCh, logger,
		)
		startCollector("network", c.Run)
	}

	if cfg.Collector.Process.Enabled {
		c := collector.NewProcessCollector(agentID, hostInfo.Hostname, eventCh, logger)
		startCollector("process", c.Run)
	}

	if cfg.Collector.Registry.Enabled {
		c := collector.NewRegistryCollector(
			cfg.Collector.Registry.Keys,
			agentID, hostInfo.Hostname, eventCh, logger,
		)
		startCollector("registry", c.Run)
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
