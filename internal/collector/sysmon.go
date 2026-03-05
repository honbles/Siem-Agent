//go:build windows

package collector

// sysmon.go — reads Sysmon events from the Microsoft-Windows-Sysmon/Operational
// event log channel and maps well-known Event IDs to enriched schema.Events.
//
// Sysmon must already be installed and running on the host.
// Ref: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"opensiem/agent/pkg/schema"
)

const sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

// sysmonEventID constants for the most security-relevant Sysmon events.
const (
	SysmonProcessCreate        = 1
	SysmonNetworkConnect       = 3
	SysmonProcessTerminate     = 5
	SysmonDriverLoad           = 6
	SysmonImageLoad            = 7
	SysmonCreateRemoteThread   = 8
	SysmonRawAccessRead        = 9
	SysmonProcessAccess        = 10
	SysmonFileCreate           = 11
	SysmonRegistryCreate       = 12
	SysmonRegistrySetValue     = 13
	SysmonRegistryRename       = 14
	SysmonFileCreateStreamHash = 15
	SysmonPipeCreated          = 17
	SysmonPipeConnected        = 18
	SysmonDNSQuery             = 22
	SysmonFileDeleteDetected   = 23
)

// sysmonEventMeta holds static metadata per Sysmon Event ID.
type sysmonEventMeta struct {
	eventType schema.EventType
	severity  schema.Severity
	name      string
}

var sysmonMeta = map[uint32]sysmonEventMeta{
	SysmonProcessCreate:        {schema.EventTypeProcess, schema.SeverityLow, "ProcessCreate"},
	SysmonNetworkConnect:       {schema.EventTypeNetwork, schema.SeverityLow, "NetworkConnect"},
	SysmonProcessTerminate:     {schema.EventTypeProcess, schema.SeverityInfo, "ProcessTerminate"},
	SysmonDriverLoad:           {schema.EventTypeProcess, schema.SeverityHigh, "DriverLoad"},
	SysmonImageLoad:            {schema.EventTypeProcess, schema.SeverityLow, "ImageLoad"},
	SysmonCreateRemoteThread:   {schema.EventTypeProcess, schema.SeverityHigh, "CreateRemoteThread"},
	SysmonRawAccessRead:        {schema.EventTypeFile, schema.SeverityHigh, "RawAccessRead"},
	SysmonProcessAccess:        {schema.EventTypeProcess, schema.SeverityMedium, "ProcessAccess"},
	SysmonFileCreate:           {schema.EventTypeFile, schema.SeverityLow, "FileCreate"},
	SysmonRegistryCreate:       {schema.EventTypeRegistry, schema.SeverityLow, "RegistryCreate"},
	SysmonRegistrySetValue:     {schema.EventTypeRegistry, schema.SeverityMedium, "RegistrySetValue"},
	SysmonRegistryRename:       {schema.EventTypeRegistry, schema.SeverityMedium, "RegistryRename"},
	SysmonFileCreateStreamHash: {schema.EventTypeFile, schema.SeverityMedium, "FileCreateStreamHash"},
	SysmonPipeCreated:          {schema.EventTypeProcess, schema.SeverityLow, "PipeCreated"},
	SysmonPipeConnected:        {schema.EventTypeProcess, schema.SeverityLow, "PipeConnected"},
	SysmonDNSQuery:             {schema.EventTypeNetwork, schema.SeverityLow, "DNSQuery"},
	SysmonFileDeleteDetected:   {schema.EventTypeFile, schema.SeverityMedium, "FileDeleteDetected"},
}

// rawSysmonEvent holds the parsed fields common across Sysmon XML payloads.
// In production this is populated by walking the XML event data nodes.
type rawSysmonEvent struct {
	EventID         uint32 `json:"EventID"`
	EventName       string `json:"EventName"`
	UtcTime         string `json:"UtcTime"`
	ProcessGUID     string `json:"ProcessGuid,omitempty"`
	ProcessID       int    `json:"ProcessId,omitempty"`
	ParentProcessID int    `json:"ParentProcessId,omitempty"`
	Image           string `json:"Image,omitempty"`
	CommandLine     string `json:"CommandLine,omitempty"`
	User            string `json:"User,omitempty"`
	Hashes          string `json:"Hashes,omitempty"`
	// Network
	DestinationIP   string `json:"DestinationIp,omitempty"`
	DestinationPort int    `json:"DestinationPort,omitempty"`
	SourceIP        string `json:"SourceIp,omitempty"`
	SourcePort      int    `json:"SourcePort,omitempty"`
	Protocol        string `json:"Protocol,omitempty"`
	// Registry
	TargetObject string `json:"TargetObject,omitempty"`
	Details      string `json:"Details,omitempty"`
	// File
	TargetFilename string `json:"TargetFilename,omitempty"`
}

// SysmonCollector wraps EventLogCollector restricted to the Sysmon channel
// and applies Sysmon-specific field mapping.
type SysmonCollector struct {
	inner   *EventLogCollector
	agentID string
	host    string
	rawIn   chan schema.Event
	out     chan<- schema.Event
	logger  *slog.Logger
}

// NewSysmonCollector creates the Sysmon collector.
func NewSysmonCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *SysmonCollector {
	rawIn := make(chan schema.Event, 512)
	return &SysmonCollector{
		inner:   NewEventLogCollector([]string{sysmonChannel}, agentID, host, rawIn, logger),
		agentID: agentID,
		host:    host,
		rawIn:   rawIn,
		out:     out,
		logger:  logger,
	}
}

// Run starts the underlying EventLog subscription and maps events.
func (s *SysmonCollector) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() { errCh <- s.inner.Run(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return <-errCh
		case ev := <-s.rawIn:
			enriched := s.mapSysmonEvent(ev)
			select {
			case s.out <- enriched:
			default:
				s.logger.Warn("sysmon: out channel full, dropping event")
			}
		}
	}
}

// mapSysmonEvent translates a raw eventlog event into a Sysmon-enriched event.
func (s *SysmonCollector) mapSysmonEvent(ev schema.Event) schema.Event {
	// Parse the raw Sysmon payload back out.
	// In production, XML parsing of ev.Raw["RawXML"] populates rawSysmon.
	var raw rawSysmonEvent
	_ = json.Unmarshal(ev.Raw, &raw) // best-effort; real impl parses XML

	raw.EventID = ev.EventID

	meta, ok := sysmonMeta[ev.EventID]
	if !ok {
		// Unknown Sysmon event — pass through with generic type.
		ev.EventType = schema.EventTypeSysmon
		ev.Source = "Sysmon"
		return ev
	}

	raw.EventName = meta.name

	// Parse UtcTime from Sysmon XML format: "2024-01-15 13:45:22.123"
	t, err := time.Parse("2006-01-02 15:04:05.000", raw.UtcTime)
	if err != nil {
		t = time.Now().UTC()
	}

	enrichedRaw, _ := json.Marshal(raw)

	return schema.Event{
		Time:        t,
		AgentID:     s.agentID,
		Host:        s.host,
		OS:          "windows",
		EventType:   meta.eventType,
		Severity:    meta.severity,
		Source:      "Sysmon",
		EventID:     ev.EventID,
		Channel:     sysmonChannel,
		PID:         raw.ProcessID,
		PPID:        raw.ParentProcessID,
		ProcessName: raw.Image,
		CommandLine: raw.CommandLine,
		UserName:    raw.User,
		FileHash:    raw.Hashes,
		DstIP:       raw.DestinationIP,
		DstPort:     raw.DestinationPort,
		SrcIP:       raw.SourceIP,
		SrcPort:     raw.SourcePort,
		Proto:       raw.Protocol,
		RegKey:      raw.TargetObject,
		RegData:     raw.Details,
		FilePath:    raw.TargetFilename,
		Raw:         enrichedRaw,
	}
}
