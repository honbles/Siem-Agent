//go:build windows

package collector

// network.go — snapshots active TCP/UDP connections using iphlpapi.dll
// (GetExtendedTcpTable / GetExtendedUdpTable), then diffs against the
// previous snapshot to emit connect/disconnect events.


import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

var (
	modIphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable  = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable  = modIphlpapi.NewProc("GetExtendedUdpTable")
)

// TCP table constants
const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	afInet              = 2
)

// MIB_TCPROW_OWNER_PID mirrors the Windows struct.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibTCPTableOwnerPID is the header + rows returned by GetExtendedTcpTable.
type mibTCPTableOwnerPID struct {
	NumEntries uint32
	Table      [1]mibTCPRowOwnerPID
}

// connKey uniquely identifies a connection for diffing.
type connKey struct {
	pid      uint32
	srcIP    string
	srcPort  int
	dstIP    string
	dstPort  int
	proto    string
}

// rawNetEvent is the JSON payload stored in Event.Raw.
type rawNetEvent struct {
	State   string `json:"state,omitempty"`
	PID     uint32 `json:"pid"`
	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
	Proto   string `json:"proto"`
}

// NetworkCollector polls active connections on an interval and emits delta events.
type NetworkCollector struct {
	interval time.Duration
	agentID  string
	host     string
	out      chan<- schema.Event
	logger   *slog.Logger
	prev     map[connKey]struct{}
}

// NewNetworkCollector creates the collector.
func NewNetworkCollector(interval time.Duration, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *NetworkCollector {
	return &NetworkCollector{
		interval: interval,
		agentID:  agentID,
		host:     host,
		out:      out,
		logger:   logger,
		prev:     make(map[connKey]struct{}),
	}
}

// Run polls at the configured interval until ctx is cancelled.
func (n *NetworkCollector) Run(ctx context.Context) error {
	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()

	// Emit a baseline snapshot immediately.
	n.snapshot()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			n.snapshot()
		}
	}
}

func (n *NetworkCollector) snapshot() {
	curr := make(map[connKey]struct{})

	tcpRows, err := getTCPTable()
	if err != nil {
		n.logger.Warn("network: getTCPTable failed", "err", err)
	}
	for _, row := range tcpRows {
		k := connKey{
			pid:     row.OwningPID,
			srcIP:   uint32ToIP(row.LocalAddr).String(),
			srcPort: int(ntohs(uint16(row.LocalPort))),
			dstIP:   uint32ToIP(row.RemoteAddr).String(),
			dstPort: int(ntohs(uint16(row.RemotePort))),
			proto:   "tcp",
		}
		curr[k] = struct{}{}
		if _, seen := n.prev[k]; !seen {
			n.emit(k, row.OwningPID, "connect")
		}
	}

	// Detect disconnects
	for k := range n.prev {
		if _, still := curr[k]; !still {
			n.emit(k, 0, "disconnect")
		}
	}
	n.prev = curr
}

func (n *NetworkCollector) emit(k connKey, pid uint32, action string) {
	raw := rawNetEvent{
		State:   action,
		PID:     pid,
		SrcIP:   k.srcIP,
		SrcPort: k.srcPort,
		DstIP:   k.dstIP,
		DstPort: k.dstPort,
		Proto:   k.proto,
	}
	rawJSON, _ := json.Marshal(raw)

	ev := schema.Event{
		Time:      time.Now().UTC(),
		AgentID:   n.agentID,
		Host:      n.host,
		OS:        "windows",
		EventType: schema.EventTypeNetwork,
		Severity:  schema.SeverityLow,
		Source:    "iphlpapi",
		PID:       int(pid),
		SrcIP:     k.srcIP,
		SrcPort:   k.srcPort,
		DstIP:     k.dstIP,
		DstPort:   k.dstPort,
		Proto:     k.proto,
		Raw:       rawJSON,
	}

	select {
	case n.out <- ev:
	default:
		n.logger.Warn("network: out channel full, dropping event")
	}
}

// getTCPTable calls GetExtendedTcpTable and returns all TCP rows.
func getTCPTable() ([]mibTCPRowOwnerPID, error) {
	var size uint32 = 4096
	buf := make([]byte, size)

	for {
		ret, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			1,                   // bOrder (sorted)
			afInet,
			tcpTableOwnerPIDAll,
			0,
		)
		if ret == 0 {
			break
		}
		if ret == 122 { // ERROR_INSUFFICIENT_BUFFER
			buf = make([]byte, size)
			continue
		}
		return nil, fmt.Errorf("GetExtendedTcpTable: %d", ret)
	}

	table := (*mibTCPTableOwnerPID)(unsafe.Pointer(&buf[0]))
	numEntries := int(table.NumEntries)
	if numEntries == 0 {
		return nil, nil
	}

	// The rows immediately follow NumEntries in memory.
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	rows := make([]mibTCPRowOwnerPID, numEntries)
	base := uintptr(unsafe.Pointer(&table.Table[0]))
	for i := 0; i < numEntries; i++ {
		rows[i] = *(*mibTCPRowOwnerPID)(unsafe.Pointer(base + uintptr(i)*rowSize))
	}
	return rows, nil
}

func uint32ToIP(addr uint32) net.IP {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	)
}

// ntohs converts network byte order uint16 to host byte order.
func ntohs(n uint16) uint16 {
	return (n>>8)|(n<<8)
}
