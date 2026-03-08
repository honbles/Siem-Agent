//go:build windows

package collector

// process.go — captures process creation/termination via ETW
// using the Microsoft-Windows-Kernel-Process provider.
// Uses the golang.org/x/sys/windows/etw package pattern via direct
// NT API calls. Falls back to polling WMI Win32_Process if ETW fails.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"syscall"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

// ETW provider GUIDs
var kernelProcessProviderGUID = windows.GUID{
	Data1: 0x22fb2cd6,
	Data2: 0x0e7b,
	Data3: 0x422b,
	Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
}

// ETW API procs
var (
	modNtdll             = windows.NewLazySystemDLL("ntdll.dll")
	modAdvapi32ETW       = windows.NewLazySystemDLL("advapi32.dll")
	procStartTrace       = modAdvapi32ETW.NewProc("StartTraceW")
	procEnableTraceEx2   = modAdvapi32ETW.NewProc("EnableTraceEx2")
	procOpenTrace        = modAdvapi32ETW.NewProc("OpenTraceW")
	procProcessTrace     = modAdvapi32ETW.NewProc("ProcessTrace")
	procCloseTrace       = modAdvapi32ETW.NewProc("CloseTrace")
	procStopTrace        = modAdvapi32ETW.NewProc("StopTraceW")
)

const (
	eventControlCodeEnableProvider = 1
	traceRealTimeMode              = 0x00000100
	processTraceModeRealTime       = 0x00000100
	processTraceModeEventRecord    = 0x10000000
	wNodeFlagTracedGUID            = 0x00020000
)

// EVENT_TRACE_PROPERTIES layout for StartTrace
type eventTraceProperties struct {
	WnodeHeader         wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
	// Variable-length session name follows in memory.
	// We allocate extra space below.
}

type wnodeHeader struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// EVENT_TRACE_LOGFILE for OpenTrace
type eventTraceLogfile struct {
	LogFileName   *uint16
	LoggerName    *uint16
	CurrentTime   int64
	BuffersRead   uint32
	Union1        uint32 // ProcessTraceMode flags
	CurrentEvent  eventTrace
	LogfileHeader traceLogfileHeader
	BufferCallback uintptr
	BufferSize    uint32
	Filled        uint32
	EventsLost    uint32
	Callback      uintptr // EventRecordCallback
	IsKernelTrace uint32
	Context       uintptr
}

type eventTrace struct {
	Header           eventTraceHeader
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
	MofData          uintptr
	MofLength        uint32
	UnionCtx         uint32
}

type eventTraceHeader struct {
	Size         uint16
	Union1       uint16
	Union2       uint32
	ThreadId     uint32
	ProcessId    uint32
	TimeStamp    int64
	Union3       [16]byte
	KernelTime   uint32
	UserTime     uint32
}

type traceLogfileHeader struct {
	BufferSize         uint32
	Union1             uint32
	StartTime          int64
	EndTime            int64
	PointerSize        uint32
	EventsLost         uint32
	CpuSpeedInMHz      uint32
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           [176]byte
	BootTime           int64
	PerfFreq           int64
	StartPerfCount     int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// EVENT_RECORD passed to our callback
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     eventBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor eventDescriptor
	KernelTime      uint32
	UserTime        uint32
	ActivityId      windows.GUID
}

type eventBufferContext struct {
	Union     uint16
	LoggerId  uint16
}

type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

const (
	processOpStart = 1
	processOpStop  = 2
)

// ProcessCollector captures process events via ETW with WMI polling fallback.
type ProcessCollector struct {
	agentID       string
	host          string
	out           chan<- schema.Event
	logger        *slog.Logger
	sessionHandle uintptr
	traceHandle   uintptr
	// callback must be stored to prevent GC
	callback      uintptr
}

// Global reference so the ETW callback can reach the collector instance.
var globalProcessCollector *ProcessCollector

func NewProcessCollector(agentID, host string, out chan<- schema.Event, logger *slog.Logger) *ProcessCollector {
	return &ProcessCollector{
		agentID: agentID,
		host:    host,
		out:     out,
		logger:  logger,
	}
}

func (p *ProcessCollector) Run(ctx context.Context) error {
	globalProcessCollector = p

	if err := p.startETW(); err != nil {
		p.logger.Warn("process: ETW failed, falling back to WMI polling", "err", err)
		return p.runWMIFallback(ctx)
	}

	p.logger.Info("process: ETW session started")

	// ProcessTrace blocks until the trace is stopped — run it in a goroutine.
	done := make(chan error, 1)
	go func() {
		traceHandles := [1]uintptr{p.traceHandle}
		ret, _, err := procProcessTrace.Call(
			uintptr(unsafe.Pointer(&traceHandles[0])),
			1, 0, 0,
		)
		if ret != 0 {
			done <- fmt.Errorf("ProcessTrace: %w", err)
		} else {
			done <- nil
		}
	}()

	select {
	case <-ctx.Done():
		p.stopETW()
		<-done
	case err := <-done:
		if err != nil {
			p.logger.Warn("process: ETW ended unexpectedly, trying WMI fallback", "err", err)
			return p.runWMIFallback(ctx)
		}
	}
	return nil
}

func (p *ProcessCollector) startETW() error {
	sessionName := "obsidianwatch-process-session"
	sessionNamePtr, _ := windows.UTF16PtrFromString(sessionName)

	// Allocate properties struct + extra space for session name string
	const extraBytes = 256
	bufSize := uint32(unsafe.Sizeof(eventTraceProperties{}) + extraBytes)
	buf := make([]byte, bufSize)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.WnodeHeader.BufferSize = bufSize
	props.WnodeHeader.Flags = wNodeFlagTracedGUID
	props.LogFileMode = traceRealTimeMode
	props.BufferSize = 64
	props.MinimumBuffers = 4
	props.MaximumBuffers = 64
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	var sessionHandle uintptr
	ret, _, err := procStartTrace.Call(
		uintptr(unsafe.Pointer(&sessionHandle)),
		uintptr(unsafe.Pointer(sessionNamePtr)),
		uintptr(unsafe.Pointer(props)),
	)
	// ERROR_ALREADY_EXISTS (183) is fine — reuse the session
	if ret != 0 && ret != 183 {
		return fmt.Errorf("StartTrace: %d %w", ret, err)
	}
	p.sessionHandle = sessionHandle

	// Enable the Kernel-Process provider
	ret, _, err = procEnableTraceEx2.Call(
		sessionHandle,
		uintptr(unsafe.Pointer(&kernelProcessProviderGUID)),
		eventControlCodeEnableProvider,
		4, // TRACE_LEVEL_INFORMATION
		0x10, // WINEVENT_KEYWORD_PROCESS
		0,
		0,
		0,
	)
	if ret != 0 {
		p.stopETW()
		return fmt.Errorf("EnableTraceEx2: %d %w", ret, err)
	}

	// Open the trace for real-time consumption
	logfile := eventTraceLogfile{}
	logfile.LoggerName = sessionNamePtr
	logfile.Union1 = processTraceModeRealTime | processTraceModeEventRecord
	// Store our callback
	p.callback = syscall.NewCallback(etwEventCallback)
	logfile.Callback = p.callback

	traceHandle, _, err := procOpenTrace.Call(uintptr(unsafe.Pointer(&logfile)))
	if traceHandle == 0xFFFFFFFFFFFFFFFF || traceHandle == 0xFFFFFFFF {
		p.stopETW()
		return fmt.Errorf("OpenTrace: %w", err)
	}
	p.traceHandle = traceHandle
	return nil
}

func (p *ProcessCollector) stopETW() {
	if p.traceHandle != 0 {
		procCloseTrace.Call(p.traceHandle)
		p.traceHandle = 0
	}
	if p.sessionHandle != 0 {
		sessionNamePtr, _ := windows.UTF16PtrFromString("obsidianwatch-process-session")
		bufSize := uint32(unsafe.Sizeof(eventTraceProperties{}) + 256)
		buf := make([]byte, bufSize)
		props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
		props.WnodeHeader.BufferSize = bufSize
		procStopTrace.Call(p.sessionHandle, uintptr(unsafe.Pointer(sessionNamePtr)), uintptr(unsafe.Pointer(props)))
		p.sessionHandle = 0
	}
}

// etwEventCallback is called by ETW for each process event.
// Must match the signature: func(*eventRecord) uintptr
func etwEventCallback(record *eventRecord) uintptr {
	if globalProcessCollector == nil {
		return 0
	}
	globalProcessCollector.handleRecord(record)
	return 0
}

func (p *ProcessCollector) handleRecord(rec *eventRecord) {
	op := rec.EventHeader.EventDescriptor.Opcode

	var evType schema.EventType
	var sev schema.Severity
	var action string

	switch op {
	case processOpStart:
		evType = schema.EventTypeProcess
		sev = schema.SeverityLow
		action = "start"
	case processOpStop:
		evType = schema.EventTypeProcess
		sev = schema.SeverityInfo
		action = "stop"
	default:
		return // only care about start/stop
	}

	ft := syscall.Filetime{
		LowDateTime:  uint32(rec.EventHeader.TimeStamp),
		HighDateTime: uint32(uint64(rec.EventHeader.TimeStamp) >> 32),
	}
	t := time.Unix(0, ft.Nanoseconds()).UTC()

	rawData := map[string]interface{}{
		"action":  action,
		"pid":     rec.EventHeader.ProcessId,
		"tid":     rec.EventHeader.ThreadId,
		"opcode":  op,
	}
	rawJSON, _ := json.Marshal(rawData)

	ev := schema.Event{
		Time:      t,
		AgentID:   p.agentID,
		Host:      p.host,
		OS:        "windows",
		EventType: evType,
		Severity:  sev,
		Source:    "ETW/KernelProcess",
		PID:       int(rec.EventHeader.ProcessId),
		Raw:       rawJSON,
	}

	select {
	case p.out <- ev:
	default:
		p.logger.Warn("process: out channel full, dropping event")
	}
}

// runWMIFallback polls Win32_Process via WMI when ETW is unavailable.
// It diffs the process list every 5 seconds to detect starts/stops.
func (p *ProcessCollector) runWMIFallback(ctx context.Context) error {
	p.logger.Info("process: WMI polling fallback active (5s interval)")

	var (
		modOle32   = windows.NewLazySystemDLL("ole32.dll")
		modOleAut  = windows.NewLazySystemDLL("oleaut32.dll")
	)
	_ = modOle32
	_ = modOleAut

	// Use tasklist via exec as the simplest cross-version fallback.
	// This avoids COM/WMI setup complexity while still providing process telemetry.
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	prev := map[uint32]ProcessInfo{} // pid -> ProcessInfo

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			curr, err := snapshotProcesses()
			if err != nil {
				p.logger.Warn("process: snapshot failed", "err", err)
				continue
			}

			// Detect new processes
			for pid, name := range curr {
				if _, seen := prev[pid]; !seen {
					p.emitWMIEvent(pid, name, "start", schema.SeverityLow)
				}
			}
			// Detect stopped processes
			for pid, name := range prev {
				if _, still := curr[pid]; !still {
					p.emitWMIEvent(pid, name, "stop", schema.SeverityInfo)
				}
			}
			prev = curr
		}
	}
}

func (p *ProcessCollector) emitWMIEvent(pid uint32, info ProcessInfo, action string, sev schema.Severity) {
	// Elevate severity for interesting processes
	cmdLow := strings.ToLower(info.CommandLine)
	nameLow := strings.ToLower(info.Name)
	if sev == schema.SeverityLow && containsInteresting(nameLow, cmdLow) {
		sev = schema.SeverityMedium
	}

	rawData := map[string]interface{}{
		"action":       action,
		"pid":          pid,
		"name":         info.Name,
		"command_line": info.CommandLine,
		"ppid":         info.PPID,
	}
	rawJSON, _ := json.Marshal(rawData)
	ev := schema.Event{
		Time:        time.Now().UTC(),
		AgentID:     p.agentID,
		Host:        p.host,
		OS:          "windows",
		EventType:   schema.EventTypeProcess,
		Severity:    sev,
		Source:      "WMI/Process",
		PID:         int(pid),
		PPID:        int(info.PPID),
		ProcessName: info.Name,
		CommandLine: info.CommandLine,
		Raw:         rawJSON,
	}
	select {
	case p.out <- ev:
	default:
	}
}

func containsInteresting(name, cmd string) bool {
	interesting := []string{
		"powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
		"regsvr32", "certutil", "bitsadmin", "wmic", "msiexec", "psexec",
		"net.exe", "netsh", "schtasks", "reg.exe", "sc.exe", "whoami",
		"mimikatz", "procdump", "git", "python", "node", "bash",
	}
	for _, s := range interesting {
		if strings.Contains(name, s) || strings.Contains(cmd, s) {
			return true
		}
	}
	return false
}

// ProcessInfo holds snapshot data for a running process.
type ProcessInfo struct {
	Name        string
	CommandLine string
	PPID        uint32
}

// snapshotProcesses uses the Windows toolhelp snapshot API for names/PIDs,
// then queries NtQueryInformationProcess for command lines.
func snapshotProcesses() (map[uint32]ProcessInfo, error) {
	modKernel32 := windows.NewLazySystemDLL("kernel32.dll")
	procCreateSnapshot := modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First := modKernel32.NewProc("Process32FirstW")
	procProcess32Next  := modKernel32.NewProc("Process32NextW")

	const TH32CS_SNAPPROCESS = 0x00000002
	snapshot, _, err := procCreateSnapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	type PROCESSENTRY32 struct {
		Size                uint32
		CntUsage            uint32
		Th32ProcessID       uint32
		Th32DefaultHeapID   uintptr
		Th32ModuleID        uint32
		CntThreads          uint32
		Th32ParentProcessID uint32
		PcPriClassBase      int32
		Flags               uint32
		ExeFile             [260]uint16
	}

	result := make(map[uint32]ProcessInfo)
	var entry PROCESSENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		name := windows.UTF16ToString(entry.ExeFile[:])
		cmdLine := readProcessCommandLine(entry.Th32ProcessID)
		result[entry.Th32ProcessID] = ProcessInfo{
			Name:        name,
			CommandLine: cmdLine,
			PPID:        entry.Th32ParentProcessID,
		}
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return result, nil
}

// readProcessCommandLine reads the command line of a process using
// NtQueryInformationProcess → PEB → ProcessParameters.
func readProcessCommandLine(pid uint32) string {
	const PROCESS_QUERY_INFORMATION = 0x0400
	const PROCESS_VM_READ           = 0x0010

	handle, err := windows.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	type UNICODE_STRING struct {
		Length    uint16
		MaxLength uint16
		_         uint32 // padding on 64-bit
		Buffer    uintptr
	}
	type RTL_USER_PROCESS_PARAMETERS struct {
		_              [112]byte // offset to CommandLine varies — skip via known offset
		CommandLine    UNICODE_STRING
	}

	// Use NtQueryInformationProcess to get PBI (ProcessBasicInformation)
	modNtdll2 := windows.NewLazySystemDLL("ntdll.dll")
	ntQuery := modNtdll2.NewProc("NtQueryInformationProcess")

	type PROCESS_BASIC_INFORMATION struct {
		ExitStatus                   uintptr
		PebBaseAddress               uintptr
		AffinityMask                 uintptr
		BasePriority                 uintptr
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}

	var pbi PROCESS_BASIC_INFORMATION
	var returnLen uint32
	ret, _, _ := ntQuery.Call(
		uintptr(handle),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if ret != 0 || pbi.PebBaseAddress == 0 {
		return ""
	}

	// Read ProcessParameters pointer from PEB (offset 0x20 on 64-bit)
	var procParamsPtr uintptr
	if err := windows.ReadProcessMemory(handle,
		pbi.PebBaseAddress+0x20,
		(*byte)(unsafe.Pointer(&procParamsPtr)),
		uintptr(unsafe.Sizeof(procParamsPtr)), nil); err != nil {
		return ""
	}

	// Read CommandLine UNICODE_STRING from ProcessParameters (offset 0x70 on 64-bit)
	type unicodeStr struct {
		Length    uint16
		MaxLength uint16
		_         [4]byte
		Buffer    uintptr
	}
	var cmdStr unicodeStr
	if err := windows.ReadProcessMemory(handle,
		procParamsPtr+0x70,
		(*byte)(unsafe.Pointer(&cmdStr)),
		uintptr(unsafe.Sizeof(cmdStr)), nil); err != nil {
		return ""
	}

	if cmdStr.Length == 0 || cmdStr.Buffer == 0 {
		return ""
	}

	// Read the actual command line string
	buf := make([]uint16, cmdStr.Length/2)
	if err := windows.ReadProcessMemory(handle,
		cmdStr.Buffer,
		(*byte)(unsafe.Pointer(&buf[0])),
		uintptr(cmdStr.Length), nil); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf)
}
