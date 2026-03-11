package schema

import (
	"encoding/json"
	"time"
)

// EventType classifies the kind of security event
type EventType string

const (
	EventTypeProcess  EventType = "process"
	EventTypeNetwork  EventType = "network"
	EventTypeLogon    EventType = "logon"
	EventTypeRegistry EventType = "registry"
	EventTypeFile     EventType = "file"
	EventTypeSysmon   EventType = "sysmon"
	EventTypeRaw      EventType = "raw"
	EventTypeDNS      EventType = "dns"
	EventTypeHealth   EventType = "health"
	EventTypeAppLog   EventType = "applog"
	EventTypeLocation EventType = "location"
)

// Severity maps to a 1–5 scale (1=info, 5=critical)
type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// Event is the normalized, centralized security event written to the DB.
type Event struct {
	ID        string          `json:"id"`
	Time      time.Time       `json:"time"`
	AgentID   string          `json:"agent_id"`
	Host      string          `json:"host"`
	OS        string          `json:"os"`
	EventType EventType       `json:"event_type"`
	Severity  Severity        `json:"severity"`
	Source    string          `json:"source"`
	Raw       json.RawMessage `json:"raw"`

	// Process fields
	PID         int    `json:"pid,omitempty"`
	PPID        int    `json:"ppid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	CommandLine string `json:"command_line,omitempty"`
	ImagePath   string `json:"image_path,omitempty"`

	// Identity fields
	UserName string `json:"user_name,omitempty"`
	Domain   string `json:"domain,omitempty"`
	LogonID  string `json:"logon_id,omitempty"`

	// Network fields
	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort int    `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"`

	// Registry fields
	RegKey   string `json:"reg_key,omitempty"`
	RegValue string `json:"reg_value,omitempty"`
	RegData  string `json:"reg_data,omitempty"`

	// File fields
	FilePath string `json:"file_path,omitempty"`
	FileHash string `json:"file_hash,omitempty"`

	// Windows Event Log fields
	EventID  uint32 `json:"event_id,omitempty"`
	Channel  string `json:"channel,omitempty"`
	RecordID uint64 `json:"record_id,omitempty"`
}

// Batch is the payload the agent POSTs to the backend ingest API.
type Batch struct {
	AgentID    string    `json:"agent_id"`
	AgentVer   string    `json:"agent_version"`
	InstallKey string    `json:"install_key,omitempty"`
	SentAt     time.Time `json:"sent_at"`
	Events     []Event   `json:"events"`
}
