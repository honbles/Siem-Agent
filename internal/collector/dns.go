//go:build windows

package collector

// dns.go — captures DNS queries and responses via the Windows Event Log
// channel Microsoft-Windows-DNS-Client/Operational.
// No Sysmon required. Works on all Windows versions with DNS Client logging enabled.
// The agent auto-enables the channel at startup if it's not already active.

import (
	"context"
	"encoding/json"
	"log/slog"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

const dnsClientChannel = "Microsoft-Windows-DNS-Client/Operational"

// DNS Event IDs in the DNS-Client/Operational channel
const (
	dnsEventQueryInitiated   = 3006 // query started
	dnsEventQueryCompleted   = 3020 // query completed with results
	dnsEventQueryFailed      = 3008 // query failed/NXDOMAIN
	dnsEventCacheHit         = 3018 // served from cache
)

// DNSCollector tails the DNS-Client/Operational event log channel.
// It wraps the EventLogCollector and adds DNS-specific field mapping.
type DNSCollector struct {
	inner   *EventLogCollector
	agentID string
	host    string
	rawIn   chan schema.Event
	out     chan<- schema.Event
	logger  *slog.Logger
}

func NewDNSCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *DNSCollector {
	rawIn := make(chan schema.Event, 512)
	return &DNSCollector{
		inner:   NewEventLogCollector([]string{dnsClientChannel}, agentID, host, rawIn, logger),
		agentID: agentID,
		host:    host,
		rawIn:   rawIn,
		out:     out,
		logger:  logger,
	}
}

func (d *DNSCollector) Run(ctx context.Context) error {
	// Enable the DNS-Client channel if it's not already enabled.
	if err := enableDNSChannel(); err != nil {
		d.logger.Warn("dns: could not enable DNS-Client channel (may need admin)", "err", err)
	}

	errCh := make(chan error, 1)
	go func() { errCh <- d.inner.Run(ctx) }()

	for {
		select {
		case <-ctx.Done():
			return <-errCh
		case ev := <-d.rawIn:
			enriched := d.mapDNSEvent(ev)
			if enriched == nil {
				continue
			}
			select {
			case d.out <- *enriched:
			default:
				d.logger.Warn("dns: out channel full, dropping event")
			}
		}
	}
}

func (d *DNSCollector) mapDNSEvent(ev schema.Event) *schema.Event {
	// Extract the event_data map from Raw (set by EventLogCollector)
	var raw map[string]interface{}
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		return nil
	}

	dataMap := map[string]string{}
	if ed, ok := raw["event_data"].(map[string]interface{}); ok {
		for k, v := range ed {
			if s, ok := v.(string); ok {
				dataMap[k] = s
			}
		}
	}

	// Only process DNS query/response events
	switch ev.EventID {
	case dnsEventQueryInitiated, dnsEventQueryCompleted, dnsEventCacheHit, dnsEventQueryFailed:
		// continue
	default:
		return nil
	}

	queryName := firstOf(dataMap, "QueryName", "Name", "DnsQueryRequest")
	queryType := firstOf(dataMap, "QueryType", "Type")
	queryResults := firstOf(dataMap, "QueryResults", "Results", "DnsQueryResults")
	queryStatus := firstOf(dataMap, "QueryStatus", "Status")

	if queryName == "" {
		return nil
	}

	sev := schema.SeverityInfo
	action := "query"
	switch ev.EventID {
	case dnsEventQueryFailed:
		sev = schema.SeverityLow
		action = "nxdomain"
	case dnsEventCacheHit:
		action = "cache_hit"
	case dnsEventQueryCompleted:
		action = "response"
	}

	enrichedRaw, _ := json.Marshal(map[string]interface{}{
		"query_name":    queryName,
		"query_type":    queryType,
		"query_results": queryResults,
		"query_status":  queryStatus,
		"action":        action,
		"pid":           ev.PID,
		"process_name":  ev.ProcessName,
	})

	return &schema.Event{
		Time:        ev.Time,
		AgentID:     d.agentID,
		Host:        d.host,
		OS:          "windows",
		EventType:   schema.EventTypeDNS,
		Severity:    sev,
		Source:      "DNS-Client",
		EventID:     ev.EventID,
		Channel:     dnsClientChannel,
		PID:         ev.PID,
		ProcessName: ev.ProcessName,
		DstIP:       queryName,    // store domain in DstIP so search/display works
		Raw:         enrichedRaw,
	}
}

// enableDNSChannel uses wevtutil logic to enable the DNS-Client channel.
// The channel is disabled by default on most Windows installs.
func enableDNSChannel() error {
	modWevtapiLocal := windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSetChannelConfig := modWevtapiLocal.NewProc("EvtSetChannelConfigProperty")
	procEvtOpenChannelConfig := modWevtapiLocal.NewProc("EvtOpenChannelConfig")
	procEvtSaveChannelConfig := modWevtapiLocal.NewProc("EvtSaveChannelConfig")

	channelPtr, _ := windows.UTF16PtrFromString(dnsClientChannel)

	handle, _, err := procEvtOpenChannelConfig.Call(
		0,
		uintptr(unsafe.Pointer(channelPtr)),
		0,
	)
	if handle == 0 {
		return err
	}
	defer func() {
		modWevtapiLocal.NewProc("EvtClose").Call(handle)
	}()

	// EvtChannelConfigEnabled = 0
	// EVT_VARIANT with type EvtVarTypeBoolean = 13, value = 1
	type evtVariant struct {
		Value uint64
		Count uint32
		Type  uint32
	}
	variant := evtVariant{Value: 1, Count: 0, Type: 13}

	ret, _, err := procEvtSetChannelConfig.Call(
		handle,
		0, // EvtChannelConfigEnabled
		0,
		uintptr(unsafe.Pointer(&variant)),
	)
	if ret == 0 {
		return err
	}

	ret, _, err = procEvtSaveChannelConfig.Call(handle, 0)
	if ret == 0 {
		return err
	}
	return nil
}
