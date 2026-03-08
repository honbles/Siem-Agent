package collector

// health.go — emits periodic agent health/heartbeat events to the SIEM backend.
// These allow the management platform to detect silent agent failures,
// monitor queue depth, dropped events, and collector status.
// Build tag: none — pure Go, cross-platform.

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

// HealthStats are updated atomically by other collectors and the forwarder.
// The HealthReporter reads them each interval and emits a heartbeat event.
type HealthStats struct {
	EventsCollected atomic.Int64
	EventsDropped   atomic.Int64
	EventsForwarded atomic.Int64
	QueueDepth      atomic.Int64
	ForwardErrors   atomic.Int64
}

// GlobalHealth is the singleton shared across the agent.
var GlobalHealth = &HealthStats{}

// HealthReporter emits a heartbeat schema.Event on a fixed interval.
type HealthReporter struct {
	interval    time.Duration
	agentID     string
	host        string
	agentVer    string
	out         chan<- schema.Event
	logger      *slog.Logger
	startTime   time.Time
	collectors  []string // names of active collectors
}

func NewHealthReporter(
	interval time.Duration,
	agentID, host, agentVer string,
	collectors []string,
	out chan<- schema.Event,
	logger *slog.Logger,
) *HealthReporter {
	return &HealthReporter{
		interval:   interval,
		agentID:    agentID,
		host:       host,
		agentVer:   agentVer,
		out:        out,
		logger:     logger,
		startTime:  time.Now(),
		collectors: collectors,
	}
}

func (h *HealthReporter) Run(ctx context.Context) error {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	// Emit one immediately at startup
	h.emit()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			h.emit()
		}
	}
}

func (h *HealthReporter) emit() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	uptime := time.Since(h.startTime).Truncate(time.Second)

	healthData := map[string]interface{}{
		"status":           "healthy",
		"uptime_seconds":   int64(uptime.Seconds()),
		"agent_version":    h.agentVer,
		"collectors":       h.collectors,
		"events_collected": GlobalHealth.EventsCollected.Load(),
		"events_dropped":   GlobalHealth.EventsDropped.Load(),
		"events_forwarded": GlobalHealth.EventsForwarded.Load(),
		"queue_depth":      GlobalHealth.QueueDepth.Load(),
		"forward_errors":   GlobalHealth.ForwardErrors.Load(),
		"memory_alloc_mb":  float64(memStats.Alloc) / 1024 / 1024,
		"goroutines":       runtime.NumGoroutine(),
		"os":               runtime.GOOS,
		"arch":             runtime.GOARCH,
	}

	rawJSON, _ := json.Marshal(healthData)

	ev := schema.Event{
		Time:      time.Now().UTC(),
		AgentID:   h.agentID,
		Host:      h.host,
		OS:        "windows",
		EventType: schema.EventTypeHealth,
		Severity:  schema.SeverityInfo,
		Source:    "agent-health",
		Raw:       rawJSON,
	}

	select {
	case h.out <- ev:
	default:
		h.logger.Warn("health: out channel full")
	}
}
