//go:build windows

package collector

// eventlog.go — reads Windows Event Log channels via wevtapi.dll.
// Full XML parsing: EventID, time, computer, user, and all EventData
// key-value pairs are extracted into normalized schema.Event fields.

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

var (
	modWevtapi                   = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe             = modWevtapi.NewProc("EvtSubscribe")
	procEvtNext                  = modWevtapi.NewProc("EvtNext")
	procEvtRender                = modWevtapi.NewProc("EvtRender")
	procEvtClose                 = modWevtapi.NewProc("EvtClose")
	procEvtFormatMessage         = modWevtapi.NewProc("EvtFormatMessage")
	procEvtOpenPublisherMetadata = modWevtapi.NewProc("EvtOpenPublisherMetadata")
)

const (
	evtSubscribeToFutureEvents = 1
	evtRenderEventXml          = 1
)

// XML structures for parsing Windows Event XML
type winEventXML struct {
	XMLName   xml.Name     `xml:"Event"`
	System    winSystemXML `xml:"System"`
	EventData winEventData `xml:"EventData"`
}

type winSystemXML struct {
	Provider    winProvider `xml:"Provider"`
	EventID     uint32      `xml:"EventID"`
	Level       uint8       `xml:"Level"`
	Task        uint16      `xml:"Task"`
	TimeCreated winTime     `xml:"TimeCreated"`
	RecordID    uint64      `xml:"EventRecordID"`
	Channel     string      `xml:"Channel"`
	Computer    string      `xml:"Computer"`
}

type winProvider struct {
	Name string `xml:"Name,attr"`
}

type winTime struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type winEventData struct {
	Data []winDataItem `xml:"Data"`
}

type winDataItem struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type EventLogCollector struct {
	channels []string
	agentID  string
	host     string
	out      chan<- schema.Event
	logger   *slog.Logger
}

func NewEventLogCollector(channels []string, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *EventLogCollector {
	return &EventLogCollector{channels: channels, agentID: agentID, host: host, out: out, logger: logger}
}

func (c *EventLogCollector) Run(ctx context.Context) error {
	handles := make([]windows.Handle, 0, len(c.channels))
	for _, ch := range c.channels {
		h, err := c.subscribe(ch)
		if err != nil {
			c.logger.Error("eventlog: subscribe failed", "channel", ch, "err", err)
			continue
		}
		handles = append(handles, h)
		c.logger.Info("eventlog: subscribed", "channel", ch)
	}
	if len(handles) == 0 {
		return fmt.Errorf("eventlog: no channels could be subscribed")
	}
	defer func() {
		for _, h := range handles {
			closeEvtHandle(h)
		}
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for _, h := range handles {
				c.drain(h)
			}
		}
	}
}

func (c *EventLogCollector) subscribe(channel string) (windows.Handle, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	queryPtr, err := windows.UTF16PtrFromString("*")
	if err != nil {
		return 0, err
	}
	signalEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(signalEvent)
	h, _, callErr := procEvtSubscribe.Call(
		0, uintptr(signalEvent),
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		0, 0, 0,
		evtSubscribeToFutureEvents,
	)
	if h == 0 {
		return 0, fmt.Errorf("EvtSubscribe: %w", callErr)
	}
	return windows.Handle(h), nil
}

func (c *EventLogCollector) drain(subHandle windows.Handle) {
	const batchSize = 64
	events := make([]windows.Handle, batchSize)
	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			uintptr(subHandle), uintptr(batchSize),
			uintptr(unsafe.Pointer(&events[0])),
			500, 0, uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}
		for i := uint32(0); i < returned; i++ {
			ev := c.parseEvent(events[i])
			closeEvtHandle(events[i])
			if ev != nil {
				select {
				case c.out <- *ev:
				default:
					c.logger.Warn("eventlog: out channel full, dropping event")
				}
			}
		}
	}
}

func (c *EventLogCollector) parseEvent(evHandle windows.Handle) *schema.Event {
	xmlBytes, err := renderXML(evHandle)
	if err != nil {
		c.logger.Warn("eventlog: render failed", "err", err)
		return nil
	}

	var parsed winEventXML
	if err := xml.Unmarshal(xmlBytes, &parsed); err != nil {
		raw, _ := json.Marshal(map[string]string{"raw_xml": string(xmlBytes)})
		return &schema.Event{
			Time: time.Now().UTC(), AgentID: c.agentID, Host: c.host, OS: "windows",
			EventType: schema.EventTypeRaw, Severity: schema.SeverityInfo,
			Source: "EventLog", Raw: raw,
		}
	}

	sys := parsed.System
	ev := &schema.Event{
		AgentID:   c.agentID,
		Host:      c.host,
		OS:        "windows",
		EventID:   sys.EventID,
		Channel:   sys.Channel,
		RecordID:  sys.RecordID,
		Source:    sys.Channel,
		Severity:  windowsLevelToSeverity(sys.Level),
		EventType: schema.EventTypeRaw,
	}

	if t, err := time.Parse(time.RFC3339Nano, sys.TimeCreated.SystemTime); err == nil {
		ev.Time = t.UTC()
	} else {
		ev.Time = time.Now().UTC()
	}

	// Build flat data map from EventData
	dataMap := make(map[string]string, len(parsed.EventData.Data))
	for _, d := range parsed.EventData.Data {
		if d.Name != "" {
			dataMap[d.Name] = strings.TrimSpace(d.Value)
		}
	}

	rawPayload := map[string]interface{}{
		"event_id": sys.EventID, "channel": sys.Channel,
		"provider": sys.Provider.Name, "record_id": sys.RecordID,
		"level": sys.Level, "event_data": dataMap,
	}
	ev.Raw, _ = json.Marshal(rawPayload)

	extractCommonFields(ev, dataMap)
	classifyAndEnrichEvent(ev, dataMap)
	return ev
}

func extractCommonFields(ev *schema.Event, data map[string]string) {
	if v := firstOf(data, "SubjectUserName", "TargetUserName", "UserName", "User"); v != "" {
		ev.UserName = v
	}
	if v := firstOf(data, "SubjectDomainName", "TargetDomainName", "Domain"); v != "" {
		ev.Domain = v
	}
	if v := firstOf(data, "SubjectLogonId", "TargetLogonId", "LogonId"); v != "" {
		ev.LogonID = v
	}
	if v := firstOf(data, "NewProcessName", "ProcessName", "Application"); v != "" {
		ev.ProcessName = v
		ev.ImagePath = v
	}
	if v := firstOf(data, "NewProcessId", "ProcessId", "ProcessID"); v != "" {
		if pid, err := parseHexOrDec(v); err == nil {
			ev.PID = pid
		}
	}
	if v := firstOf(data, "ParentProcessId", "ParentProcessID"); v != "" {
		if ppid, err := parseHexOrDec(v); err == nil {
			ev.PPID = ppid
		}
	}
	if v := data["CommandLine"]; v != "" {
		ev.CommandLine = v
	}
}

func classifyAndEnrichEvent(ev *schema.Event, data map[string]string) {
	switch ev.EventID {
	case 4624:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityInfo
		if lt := data["LogonType"]; lt != "" {
			ev.Severity = logonTypeSeverity(lt)
		}
	case 4625:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityMedium
		if data["LogonType"] == "3" {
			ev.Severity = schema.SeverityHigh
		}
	case 4648:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityMedium
		if v := data["TargetServerName"]; v != "" {
			ev.DstIP = v
		}
	case 4672:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityMedium
	case 4634, 4647:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityInfo
	case 4776:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityLow
		if v := data["Workstation"]; v != "" {
			ev.SrcIP = v
		}
	case 4688:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityLow
	case 4689:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityInfo
	case 5156:
		ev.EventType = schema.EventTypeNetwork
		ev.Severity = schema.SeverityLow
		ev.SrcIP = data["SourceAddress"]
		ev.DstIP = data["DestAddress"]
		if p, err := strconv.Atoi(data["SourcePort"]); err == nil {
			ev.SrcPort = p
		}
		if p, err := strconv.Atoi(data["DestPort"]); err == nil {
			ev.DstPort = p
		}
		ev.Proto = protocolNumber(data["Protocol"])
	case 5157:
		ev.EventType = schema.EventTypeNetwork
		ev.Severity = schema.SeverityMedium
		ev.SrcIP = data["SourceAddress"]
		ev.DstIP = data["DestAddress"]
		if p, err := strconv.Atoi(data["SourcePort"]); err == nil {
			ev.SrcPort = p
		}
		if p, err := strconv.Atoi(data["DestPort"]); err == nil {
			ev.DstPort = p
		}
		ev.Proto = protocolNumber(data["Protocol"])
	case 4657:
		ev.EventType = schema.EventTypeRegistry
		ev.Severity = schema.SeverityMedium
		ev.RegKey = data["ObjectName"]
		ev.RegValue = data["ObjectValueName"]
		ev.RegData = data["NewValue"]
	case 4663:
		ev.EventType = schema.EventTypeFile
		ev.Severity = schema.SeverityLow
		ev.FilePath = data["ObjectName"]
	case 4660:
		ev.EventType = schema.EventTypeFile
		ev.Severity = schema.SeverityMedium
		ev.FilePath = data["ObjectName"]
	case 4698, 4702:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityHigh
	case 4720:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityHigh
	case 4728, 4732, 4756:
		ev.EventType = schema.EventTypeLogon
		ev.Severity = schema.SeverityHigh
	case 7045:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityHigh
		if v := data["ServiceName"]; v != "" {
			ev.ProcessName = v
		}
		if v := data["ImagePath"]; v != "" {
			ev.ImagePath = v
		}
	// PowerShell — Module logging (4103) and Script Block logging (4104)
	case 4103:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityLow
		ev.ProcessName = "powershell"
		// Payload contains the actual command/script that ran
		if v := firstOf(data, "Payload", "ScriptBlockText", "MessageNumber"); v != "" {
			ev.CommandLine = v
		}
		if v := firstOf(data, "HostApplication", "Path"); v != "" {
			ev.ImagePath = v
		}
		// Mark as suspicious if contains common attack patterns
		cmdLower := strings.ToLower(ev.CommandLine)
		if containsAnyStr(cmdLower, "-enc", "downloadstring", "iex", "invoke-expression",
			"webclient", "bypass", "hidden", "frombase64", "reflection.assembly") {
			ev.Severity = schema.SeverityHigh
		}
	case 4104:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityLow
		ev.ProcessName = "powershell"
		// 4104 = Script Block Logging — captures the ACTUAL script text
		if v := firstOf(data, "ScriptBlockText", "Payload"); v != "" {
			ev.CommandLine = v
		}
		if v := data["Path"]; v != "" {
			ev.ImagePath = v
		}
		cmdLower := strings.ToLower(ev.CommandLine)
		if containsAnyStr(cmdLower, "-enc", "downloadstring", "iex", "invoke-expression",
			"webclient", "bypass", "hidden", "frombase64", "reflection.assembly",
			"mimikatz", "invoke-mimikatz", "shellcode") {
			ev.Severity = schema.SeverityHigh
		}
	// Windows Defender detections
	case 1116, 1117:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityCritical
		if v := firstOf(data, "Threat Name", "ThreatName"); v != "" {
			ev.ProcessName = v
		}
		if v := firstOf(data, "Path", "Process Name"); v != "" {
			ev.FilePath = v
		}
	// AppLocker blocked execution
	case 8004, 8007:
		ev.EventType = schema.EventTypeProcess
		ev.Severity = schema.SeverityHigh
		if v := firstOf(data, "FilePath", "FullFilePath"); v != "" {
			ev.FilePath = v
			ev.ImagePath = v
		}
		if v := data["User"]; v != "" {
			ev.UserName = v
		}
	}
}

func containsAnyStr(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func renderXML(evHandle windows.Handle) ([]byte, error) {
	var bufSize uint32 = 4096
	buf := make([]uint16, bufSize)
	var used, propCount uint32
	ret, _, err := procEvtRender.Call(
		0, uintptr(evHandle), evtRenderEventXml,
		uintptr(bufSize*2), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)),
	)
	if ret == 0 {
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]uint16, used/2+1)
			ret, _, err = procEvtRender.Call(
				0, uintptr(evHandle), evtRenderEventXml,
				uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)),
			)
			if ret == 0 {
				return nil, fmt.Errorf("EvtRender retry: %w", err)
			}
		} else {
			return nil, fmt.Errorf("EvtRender: %w", err)
		}
	}
	return []byte(windows.UTF16ToString(buf)), nil
}

func closeEvtHandle(h windows.Handle) { procEvtClose.Call(uintptr(h)) }

func windowsLevelToSeverity(level uint8) schema.Severity {
	switch level {
	case 1:
		return schema.SeverityCritical
	case 2:
		return schema.SeverityHigh
	case 3:
		return schema.SeverityMedium
	default:
		return schema.SeverityInfo
	}
}

func logonTypeSeverity(logonType string) schema.Severity {
	switch logonType {
	case "10":
		return schema.SeverityMedium // RemoteInteractive (RDP)
	case "3":
		return schema.SeverityLow // Network
	default:
		return schema.SeverityInfo
	}
}

func protocolNumber(p string) string {
	switch p {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "1":
		return "icmp"
	default:
		return p
	}
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; v != "" && v != "-" {
			return v
		}
	}
	return ""
}

func parseHexOrDec(s string) (int, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return int(v), err
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return int(v), err
}
