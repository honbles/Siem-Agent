package parser

// enricher.go — adds context that the raw collector cannot provide:
//   - resolved hostname and OS version
//   - agent ID stamped from config
//   - a deterministic UUID for the event
//   - geo/ASN enrichment stub (plug in MaxMind, etc.)

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"obsidianwatch/agent/pkg/schema"
)

// HostInfo captures static host metadata resolved once at startup.
type HostInfo struct {
	Hostname  string
	OS        string
	AgentID   string
	AgentVer  string
}

// ResolveHostInfo collects static host metadata.
func ResolveHostInfo(agentID, agentVer string) HostInfo {
	h, _ := os.Hostname()
	return HostInfo{
		Hostname: h,
		OS:       normaliseOS(runtime.GOOS),
		AgentID:  agentID,
		AgentVer: agentVer,
	}
}

// Enricher stamps events with host context and computed fields.
type Enricher struct {
	host   HostInfo
	logger *slog.Logger
}

// NewEnricher creates an Enricher.
func NewEnricher(host HostInfo, logger *slog.Logger) *Enricher {
	return &Enricher{host: host, logger: logger}
}

// Enrich stamps a single event with agent/host context and a deterministic ID.
func (e *Enricher) Enrich(ev *schema.Event) {
	// Always override agent identity — collectors should not forge these.
	ev.AgentID = e.host.AgentID
	ev.Host    = e.host.Hostname
	ev.OS      = e.host.OS

	// Assign a deterministic ID based on (time, agent, source, record_id)
	// so duplicate deliveries can be deduplicated on the backend.
	ev.ID = deterministicID(ev)

	// Enrich destination IP with private/public classification.
	if ev.DstIP != "" {
		ev.DstIP = sanitizeIP(ev.DstIP)
	}
}

// EnrichBatch enriches a slice of events in-place.
func (e *Enricher) EnrichBatch(events []schema.Event) {
	for i := range events {
		e.Enrich(&events[i])
	}
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

// deterministicID returns a hex-encoded 128-bit SHA-256 derived ID.
// This is NOT cryptographically unique — it is a best-effort dedup key.
func deterministicID(ev *schema.Event) string {
	h := sha256.New()
	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(ev.Time.UnixNano()))
	h.Write(ts)
	fmt.Fprintf(h, "%s|%s|%s|%d|%d", ev.AgentID, ev.Source, ev.EventType, ev.EventID, ev.RecordID)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

// ---------------------------------------------------------------------------
// IP helpers
// ---------------------------------------------------------------------------

func sanitizeIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ip
	}
	return parsed.String()
}

// IsPrivateIP returns true if the IP is in RFC1918 / loopback / link-local.
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range private {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// OS normalisation
// ---------------------------------------------------------------------------

func normaliseOS(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	default:
		return goos
	}
}

// ---------------------------------------------------------------------------
// GeoIP enrichment stub
// ---------------------------------------------------------------------------

// GeoInfo holds optional geo/ASN data for an IP.
type GeoInfo struct {
	Country string
	City    string
	ASN     uint32
	Org     string
}

// GeoEnricher is a pluggable interface — swap in MaxMind, ip-api, etc.
type GeoEnricher interface {
	Lookup(ip string) (*GeoInfo, error)
}

// NoopGeoEnricher returns empty results; used when geo is not configured.
type NoopGeoEnricher struct{}

func (n NoopGeoEnricher) Lookup(_ string) (*GeoInfo, error) {
	return &GeoInfo{}, nil
}

// TimeToAge returns a human-readable age string for logging/debugging.
func TimeToAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%.0fs ago", d.Seconds())
	default:
		return fmt.Sprintf("%.0fm ago", d.Minutes())
	}
}
