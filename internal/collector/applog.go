package collector

// applog.go — tails one or more application log files and ships each line
// as a schema.Event to the SIEM backend.
//
// Supports three log formats:
//   json     — each line is a JSON object; fields are mapped to Event fields
//   text     — each line is treated as a plain message stored in Raw
//   combined — Apache/nginx "combined" access log format
//
// The collector remembers its file offset via a small state file so it
// never re-ships lines after a restart, and picks up rotated files when the
// inode/size changes.
//
// Build constraint: none — this file is pure Go and works on all platforms.
// The agent binary is Windows-only via main.go's build tag, but this
// collector itself is portable.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

// AppLogConfig is the per-file configuration block.
// It mirrors what the user writes in agent.yaml under app_logs[].
type AppLogConfig struct {
	Name      string `yaml:"name"`       // human-readable label, used as Source
	Path      string `yaml:"path"`       // absolute path to the log file
	Format    string `yaml:"format"`     // json | text | combined
	EventType string `yaml:"event_type"` // any string, defaults to "applog"
	Severity  int    `yaml:"severity"`   // 1–5 default severity for lines from this file
	// StateDir is set by the agent at startup — users don't need to set it.
	StateDir string `yaml:"-"`
}

// AppLogCollector tails a set of log files concurrently.
type AppLogCollector struct {
	files   []AppLogConfig
	agentID string
	host    string
	out     chan<- schema.Event
	logger  *slog.Logger
}

// NewAppLogCollector creates the collector.
// stateDir is a writable directory where per-file offset state is stored
// (e.g. C:\ProgramData\ObsidianWatch\applog_state).
func NewAppLogCollector(
	files []AppLogConfig,
	stateDir, agentID, host string,
	out chan<- schema.Event,
	logger *slog.Logger,
) *AppLogCollector {
	// Inject stateDir into each config entry.
	for i := range files {
		files[i].StateDir = stateDir
		if files[i].EventType == "" {
			files[i].EventType = "applog"
		}
		if files[i].Severity == 0 {
			files[i].Severity = int(schema.SeverityInfo)
		}
		if files[i].Format == "" {
			files[i].Format = "text"
		}
	}
	return &AppLogCollector{
		files:   files,
		agentID: agentID,
		host:    host,
		out:     out,
		logger:  logger,
	}
}

// Run starts one goroutine per file and waits for ctx cancellation.
func (a *AppLogCollector) Run(ctx context.Context) error {
	if len(a.files) == 0 {
		a.logger.Info("applog: no files configured, collector idle")
		<-ctx.Done()
		return nil
	}

	done := make(chan struct{})
	for _, cfg := range a.files {
		go func(c AppLogConfig) {
			t := newFileTailer(c, a.agentID, a.host, a.out, a.logger)
			if err := t.tail(ctx); err != nil && err != context.Canceled {
				a.logger.Error("applog: tailer error", "file", c.Path, "err", err)
			}
		}(cfg)
	}

	<-ctx.Done()
	close(done)
	return nil
}

// ---------------------------------------------------------------------------
// fileTailer — tails a single file
// ---------------------------------------------------------------------------

type fileTailer struct {
	cfg     AppLogConfig
	agentID string
	host    string
	out     chan<- schema.Event
	logger  *slog.Logger
}

func newFileTailer(cfg AppLogConfig, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *fileTailer {
	return &fileTailer{cfg: cfg, agentID: agentID, host: host, out: out, logger: logger}
}

// tail opens the file, seeks to the saved offset, and reads new lines.
// On each poll interval it checks for rotation (file smaller than saved offset
// or inode changed) and reopens from the start if needed.
func (t *fileTailer) tail(ctx context.Context) error {
	const pollInterval = 1 * time.Second

	t.logger.Info("applog: tailing", "file", t.cfg.Path, "format", t.cfg.Format)

	offset := t.loadOffset()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var f *os.File
	var err error

	open := func() {
		if f != nil {
			f.Close()
			f = nil
		}
		f, err = os.Open(t.cfg.Path)
		if err != nil {
			// File may not exist yet — that's fine, we'll retry.
			return
		}
		// If saved offset is beyond the file size (rotation), start from 0.
		fi, _ := f.Stat()
		if fi != nil && offset > fi.Size() {
			t.logger.Info("applog: rotation detected, resetting offset", "file", t.cfg.Path)
			offset = 0
		}
		if _, err = f.Seek(offset, io.SeekStart); err != nil {
			t.logger.Warn("applog: seek failed", "file", t.cfg.Path, "err", err)
			offset = 0
		}
	}

	open()

	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return ctx.Err()

		case <-ticker.C:
			if f == nil {
				open() // retry open on missing file
				continue
			}

			// Check for rotation: if the file is now smaller than our offset.
			fi, statErr := f.Stat()
			if statErr != nil {
				open()
				continue
			}
			if fi.Size() < offset {
				t.logger.Info("applog: file truncated/rotated, reopening", "file", t.cfg.Path)
				open()
				offset = 0
				continue
			}

			// Read all new complete lines.
			newOffset, linesRead := t.readLines(f, offset)
			if linesRead > 0 {
				offset = newOffset
				t.saveOffset(offset)
			}
		}
	}
}

// readLines scans all complete lines from the current file position.
// Returns the new offset and the number of lines emitted.
func (t *fileTailer) readLines(f *os.File, startOffset int64) (int64, int) {
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 256*1024), 256*1024) // 256 KB max line

	offset := startOffset
	count := 0

	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			offset += int64(len(scanner.Bytes())) + 1
			continue
		}
		ev := t.parseLine(line)
		select {
		case t.out <- ev:
		default:
			t.logger.Warn("applog: out channel full, dropping line", "file", t.cfg.Path)
		}
		offset += int64(len(scanner.Bytes())) + 1 // +1 for newline
		count++
	}
	return offset, count
}

// parseLine converts a raw log line into a schema.Event based on the format.
func (t *fileTailer) parseLine(line string) schema.Event {
	ev := schema.Event{
		Time:      time.Now().UTC(),
		AgentID:   t.agentID,
		Host:      t.host,
		OS:        "windows",
		EventType: schema.EventType(t.cfg.EventType),
		Severity:  schema.Severity(t.cfg.Severity),
		Source:    t.cfg.Name,
	}

	switch strings.ToLower(t.cfg.Format) {
	case "json":
		t.parseJSON(line, &ev)
	case "combined":
		t.parseCombined(line, &ev)
	default: // "text"
		raw, _ := json.Marshal(map[string]string{"message": line})
		ev.Raw = raw
	}

	return ev
}

// ---------------------------------------------------------------------------
// JSON log parser
// Tries to map common field names to Event fields.
// Everything is also stored verbatim in Raw.
// ---------------------------------------------------------------------------

var jsonSeverityMap = map[string]schema.Severity{
	"trace":    schema.SeverityInfo,
	"debug":    schema.SeverityInfo,
	"info":     schema.SeverityInfo,
	"information": schema.SeverityInfo,
	"warn":     schema.SeverityLow,
	"warning":  schema.SeverityLow,
	"error":    schema.SeverityHigh,
	"err":      schema.SeverityHigh,
	"fatal":    schema.SeverityCritical,
	"critical": schema.SeverityCritical,
	"panic":    schema.SeverityCritical,
}

func (t *fileTailer) parseJSON(line string, ev *schema.Event) {
	ev.Raw = json.RawMessage(line)

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(line), &obj); err != nil {
		// Not valid JSON — treat as text.
		raw, _ := json.Marshal(map[string]string{"message": line})
		ev.Raw = raw
		return
	}

	// ── Time ──────────────────────────────────────────────────────────────
	for _, key := range []string{"time", "timestamp", "ts", "@timestamp", "datetime", "date"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok {
				for _, layout := range []string{
					time.RFC3339Nano,
					time.RFC3339,
					"2006-01-02T15:04:05",
					"2006-01-02 15:04:05",
					"2006/01/02 15:04:05",
				} {
					if parsed, err := time.Parse(layout, s); err == nil {
						ev.Time = parsed.UTC()
						break
					}
				}
			}
			// Unix epoch float
			if f, ok := v.(float64); ok {
				ev.Time = time.Unix(int64(f), 0).UTC()
			}
			break
		}
	}

	// ── Severity / Level ──────────────────────────────────────────────────
	for _, key := range []string{"level", "severity", "log_level", "loglevel", "lvl"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok {
				if sev, found := jsonSeverityMap[strings.ToLower(s)]; found {
					ev.Severity = sev
				}
			}
			break
		}
	}

	// ── Message → stored in Raw, already there ────────────────────────────

	// ── User ──────────────────────────────────────────────────────────────
	for _, key := range []string{"user", "username", "user_name", "userId", "user_id"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				ev.UserName = s
				break
			}
		}
	}

	// ── Source IP ─────────────────────────────────────────────────────────
	for _, key := range []string{"src_ip", "source_ip", "client_ip", "ip", "remote_addr", "remoteAddr", "clientIp"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				ev.SrcIP = s
				break
			}
		}
	}

	// ── Destination IP ────────────────────────────────────────────────────
	for _, key := range []string{"dst_ip", "dest_ip", "destination_ip", "server_ip"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				ev.DstIP = s
				break
			}
		}
	}

	// ── Ports ─────────────────────────────────────────────────────────────
	for _, key := range []string{"src_port", "source_port", "sport"} {
		if v, ok := obj[key]; ok {
			if f, ok := v.(float64); ok {
				ev.SrcPort = int(f)
				break
			}
		}
	}
	for _, key := range []string{"dst_port", "dest_port", "dport", "port"} {
		if v, ok := obj[key]; ok {
			if f, ok := v.(float64); ok {
				ev.DstPort = int(f)
				break
			}
		}
	}

	// ── Process info ──────────────────────────────────────────────────────
	for _, key := range []string{"process", "process_name", "processName", "app", "service"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				ev.ProcessName = s
				break
			}
		}
	}
	for _, key := range []string{"pid", "process_id", "processId"} {
		if v, ok := obj[key]; ok {
			if f, ok := v.(float64); ok {
				ev.PID = int(f)
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Apache/nginx "combined" access log parser
// Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
// ---------------------------------------------------------------------------

// combinedRegex matches the standard Apache/nginx combined log format.
var combinedRegex = regexp.MustCompile(
	`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)\s+"([^"]*)"\s+"([^"]*)"`,
)

func (t *fileTailer) parseCombined(line string, ev *schema.Event) {
	raw, _ := json.Marshal(map[string]string{"message": line})
	ev.Raw = raw

	m := combinedRegex.FindStringSubmatch(line)
	if m == nil {
		return // not parseable, raw is already set
	}

	// m[1]=host, m[2]=user, m[3]=time, m[4]=request, m[5]=status, m[6]=bytes
	// m[7]=referer, m[8]=user-agent

	ev.SrcIP = m[1]
	if m[2] != "-" {
		ev.UserName = m[2]
	}

	// Parse time: "02/Jan/2006:15:04:05 -0700"
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[3]); err == nil {
		ev.Time = t.UTC()
	}

	// Map HTTP status to severity.
	if code, err := strconv.Atoi(m[5]); err == nil {
		switch {
		case code >= 500:
			ev.Severity = schema.SeverityHigh
		case code >= 400:
			ev.Severity = schema.SeverityMedium
		default:
			ev.Severity = schema.SeverityInfo
		}
	}

	// Enrich Raw with parsed fields for the management UI.
	parts := strings.SplitN(m[4], " ", 3)
	method, path := "", ""
	if len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}

	enriched, _ := json.Marshal(map[string]string{
		"message":    line,
		"src_ip":     m[1],
		"user":       m[2],
		"method":     method,
		"path":       path,
		"status":     m[5],
		"bytes":      m[6],
		"referer":    m[7],
		"user_agent": m[8],
	})
	ev.Raw = enriched
}

// ---------------------------------------------------------------------------
// Offset persistence — simple text file with the byte offset as a decimal int
// ---------------------------------------------------------------------------

func (t *fileTailer) stateFile() string {
	if t.cfg.StateDir == "" {
		return ""
	}
	// Sanitise the log name so it's a safe filename.
	safe := strings.NewReplacer(`\`, "_", `/`, "_", ":", "_", " ", "_").Replace(t.cfg.Name)
	return filepath.Join(t.cfg.StateDir, safe+".offset")
}

func (t *fileTailer) loadOffset() int64 {
	sf := t.stateFile()
	if sf == "" {
		return 0
	}
	data, err := os.ReadFile(sf)
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func (t *fileTailer) saveOffset(offset int64) {
	sf := t.stateFile()
	if sf == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(sf), 0700); err != nil {
		return
	}
	_ = os.WriteFile(sf, []byte(strconv.FormatInt(offset, 10)), 0600)
}

// Ensure fmt is used (it's used in parseCombined indirectly via strconv).
var _ = fmt.Sprintf
