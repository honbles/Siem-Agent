package parser

// normalizer.go — maps raw collector events to a clean, canonical schema.Event.
// The normalizer is the single place where field names, severity mappings,
// and event type classifications are standardised across all sources.

import (
	"fmt"
	"log/slog"
	"strings"

	"obsidianwatch/agent/pkg/schema"
)

// Normalizer applies normalization rules to raw schema.Events.
type Normalizer struct {
	logger *slog.Logger
}

// NewNormalizer creates a Normalizer.
func NewNormalizer(logger *slog.Logger) *Normalizer {
	return &Normalizer{logger: logger}
}

// Normalize cleans and validates a single event in-place.
// Returns an error if the event is malformed and should be dropped.
func (n *Normalizer) Normalize(ev *schema.Event) error {
	if ev == nil {
		return fmt.Errorf("nil event")
	}

	// ── Required fields ────────────────────────────────────────────────────
	if ev.AgentID == "" {
		return fmt.Errorf("missing agent_id")
	}
	if ev.Host == "" {
		return fmt.Errorf("missing host")
	}
	if ev.Time.IsZero() {
		return fmt.Errorf("missing time")
	}

	// ── EventType fallback ─────────────────────────────────────────────────
	if ev.EventType == "" {
		ev.EventType = classifyByEventID(ev.EventID, ev.Source)
	}

	// ── Severity floor ─────────────────────────────────────────────────────
	if ev.Severity == 0 {
		ev.Severity = schema.SeverityInfo
	}

	// ── String hygiene ─────────────────────────────────────────────────────
	ev.UserName = sanitize(ev.UserName)
	ev.Domain   = sanitize(ev.Domain)
	ev.CommandLine = truncate(ev.CommandLine, 4096)
	ev.FilePath    = sanitize(ev.FilePath)
	ev.RegKey      = sanitize(ev.RegKey)

	// ── Well-known EventID enrichment (Windows Security channel) ──────────
	ev.Severity = adjustSeverityByEventID(ev.EventID, ev.Severity)

	// ── OS normalisation ───────────────────────────────────────────────────
	ev.OS = strings.ToLower(ev.OS)
	if ev.OS == "" {
		ev.OS = "windows"
	}

	return nil
}

// NormalizeBatch normalises a slice in-place, removing invalid events.
func (n *Normalizer) NormalizeBatch(events []schema.Event) []schema.Event {
	out := events[:0]
	for i := range events {
		if err := n.Normalize(&events[i]); err != nil {
			n.logger.Debug("normalizer: dropping event", "err", err, "source", events[i].Source)
			continue
		}
		out = append(out, events[i])
	}
	return out
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

// classifyByEventID applies Windows Security EventID → EventType mapping
// for common event IDs when the source is ambiguous.
func classifyByEventID(id uint32, source string) schema.EventType {
	if strings.EqualFold(source, "Sysmon") {
		return schema.EventTypeSysmon
	}

	switch id {
	// Logon / logoff
	case 4624, 4625, 4634, 4647, 4648, 4672, 4800, 4801:
		return schema.EventTypeLogon
	// Process
	case 4688, 4689:
		return schema.EventTypeProcess
	// Object access / file
	case 4656, 4663, 4660:
		return schema.EventTypeFile
	// Registry
	case 4657:
		return schema.EventTypeRegistry
	// Network
	case 5156, 5157, 5158, 5159:
		return schema.EventTypeNetwork
	default:
		return schema.EventTypeRaw
	}
}

// adjustSeverityByEventID raises the severity for high-signal Windows events.
func adjustSeverityByEventID(id uint32, current schema.Severity) schema.Severity {
	highSeverityIDs := map[uint32]schema.Severity{
		4625: schema.SeverityMedium,  // failed logon
		4648: schema.SeverityMedium,  // explicit credential use
		4672: schema.SeverityMedium,  // admin logon
		4698: schema.SeverityHigh,    // scheduled task created
		4702: schema.SeverityHigh,    // scheduled task updated
		4720: schema.SeverityHigh,    // user account created
		4728: schema.SeverityHigh,    // member added to security group
		4732: schema.SeverityHigh,    // member added to local group
		4756: schema.SeverityHigh,    // member added to universal group
		4776: schema.SeverityMedium,  // credential validation
		5156: schema.SeverityLow,     // network connection allowed
		5157: schema.SeverityMedium,  // network connection blocked
	}

	if mapped, ok := highSeverityIDs[id]; ok {
		if mapped > current {
			return mapped
		}
	}
	return current
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	// Replace null bytes that can appear in raw Windows strings.
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…[truncated]"
}
