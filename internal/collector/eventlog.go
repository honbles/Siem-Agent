//go:build windows

package collector

// eventlog.go — reads Windows Security/System/Application event log channels
// using the Windows Event Log API (wevtapi.dll via golang.org/x/sys/windows).
//
// Build constraint: windows only.
// On non-Windows systems this file is excluded from compilation.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"opensiem/agent/pkg/schema"
)

// wevtapi function pointers loaded once at startup.
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
	evtSubscribeToFutureEvents      = 1
	evtSubscribeStartAtOldestRecord = 2
	evtRenderEventXml               = 1
)

// rawWinEvent is the minimal XML-decoded representation we pull from the API.
type rawWinEvent struct {
	EventID     uint32 `json:"EventID"`
	Channel     string `json:"Channel"`
	RecordID    uint64 `json:"RecordID"`
	TimeCreated string `json:"TimeCreated"`
	Computer    string `json:"Computer"`
	UserID      string `json:"UserID"`
	Level       uint8  `json:"Level"`
	Task        uint16 `json:"Task"`
	RawXML      string `json:"RawXML"`
}

// EventLogCollector subscribes to one or more Windows Event Log channels
// and emits normalized schema.Events on the out channel.
type EventLogCollector struct {
	channels []string
	agentID  string
	host     string
	out      chan<- schema.Event
	logger   *slog.Logger
}

// NewEventLogCollector creates the collector. out must be a buffered channel.
func NewEventLogCollector(channels []string, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *EventLogCollector {
	return &EventLogCollector{
		channels: channels,
		agentID:  agentID,
		host:     host,
		out:      out,
		logger:   logger,
	}
}

// Run subscribes to each channel and blocks until ctx is cancelled.
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
			closeHandle(h)
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

// subscribe opens a push subscription to the channel, returning the query handle.
func (c *EventLogCollector) subscribe(channel string) (windows.Handle, error) {
	channelPtr, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	// "*" = all events
	queryPtr, err := windows.UTF16PtrFromString("*")
	if err != nil {
		return 0, err
	}

	h, _, err := procEvtSubscribe.Call(
		0, // session (local)
		0, // signalEvent
		uintptr(unsafe.Pointer(channelPtr)),
		uintptr(unsafe.Pointer(queryPtr)),
		0, // bookmark
		0, // context
		0, // callback (pull mode)
		evtSubscribeToFutureEvents,
	)
	if h == 0 {
		return 0, fmt.Errorf("EvtSubscribe: %w", err)
	}
	return windows.Handle(h), nil
}

// drain reads all pending events from a subscription handle.
func (c *EventLogCollector) drain(subHandle windows.Handle) {
	const batchSize = 64
	events := make([]windows.Handle, batchSize)

	for {
		var returned uint32
		ret, _, _ := procEvtNext.Call(
			uintptr(subHandle),
			uintptr(batchSize),
			uintptr(unsafe.Pointer(&events[0])),
			500, // timeout ms
			0,
			uintptr(unsafe.Pointer(&returned)),
		)
		if ret == 0 || returned == 0 {
			break
		}

		for i := uint32(0); i < returned; i++ {
			ev := c.renderEvent(events[i])
			closeHandle(events[i])
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

// renderEvent renders a single event handle into a schema.Event.
func (c *EventLogCollector) renderEvent(evHandle windows.Handle) *schema.Event {
	xmlBytes, err := renderXML(evHandle)
	if err != nil {
		c.logger.Warn("eventlog: render failed", "err", err)
		return nil
	}

	raw := rawWinEvent{RawXML: string(xmlBytes)}
	// In production, parse the XML into raw fields here.
	// We store the full XML in Raw for forensic fidelity.
	rawJSON, _ := json.Marshal(raw)

	sev := windowsLevelToSeverity(raw.Level)

	return &schema.Event{
		Time:      time.Now().UTC(),
		AgentID:   c.agentID,
		Host:      c.host,
		OS:        "windows",
		EventType: schema.EventTypeRaw,
		Severity:  sev,
		Source:    raw.Channel,
		EventID:   raw.EventID,
		Channel:   raw.Channel,
		RecordID:  raw.RecordID,
		Raw:       rawJSON,
	}
}

// renderXML calls EvtRender with EvtRenderEventXml flag.
func renderXML(evHandle windows.Handle) ([]byte, error) {
	var bufSize uint32 = 4096
	buf := make([]uint16, bufSize)
	var used, propCount uint32

	ret, _, err := procEvtRender.Call(
		0,
		uintptr(evHandle),
		evtRenderEventXml,
		uintptr(bufSize*2),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)),
		uintptr(unsafe.Pointer(&propCount)),
	)

	if ret == 0 {
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			buf = make([]uint16, used/2+1)
			ret, _, err = procEvtRender.Call(
				0, uintptr(evHandle), evtRenderEventXml,
				uintptr(len(buf)*2),
				uintptr(unsafe.Pointer(&buf[0])),
				uintptr(unsafe.Pointer(&used)),
				uintptr(unsafe.Pointer(&propCount)),
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

func closeHandle(h windows.Handle) {
	procEvtClose.Call(uintptr(h)) //nolint:errcheck
}

// windowsLevelToSeverity maps Windows event log level (0–5) to our schema.
func windowsLevelToSeverity(level uint8) schema.Severity {
	switch level {
	case 1: // Critical
		return schema.SeverityCritical
	case 2: // Error
		return schema.SeverityHigh
	case 3: // Warning
		return schema.SeverityMedium
	default:
		return schema.SeverityInfo
	}
}
