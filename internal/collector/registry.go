//go:build windows

package collector

// registry.go — watches configured Windows registry keys for changes
// using RegNotifyChangeKeyValue and emits schema.Events on mutation.


import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows/registry"

	"golang.org/x/sys/windows"

	"obsidianwatch/agent/pkg/schema"
)

// notifyFilter controls what changes trigger a notification.
const (
	regNotifyChangeName      = 0x00000001 // key created/deleted
	regNotifyChangeAttributes = 0x00000002 // key attributes
	regNotifyChangeLastSet   = 0x00000004 // value modification
	regNotifyChangeSecurity  = 0x00000008 // security descriptor

	// We watch for name + value changes.
	regNotifyFilter = regNotifyChangeName | regNotifyChangeLastSet
)

// rawRegEvent is stored in Event.Raw.
type rawRegEvent struct {
	Key       string `json:"key"`
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
}

// registryWatcher watches a single registry key subtree.
type registryWatcher struct {
	keyPath string
	hive    registry.Key
	subKey  string
	handle  registry.Key
	event   windows.Handle
}

// RegistryCollector watches a set of registry keys and emits change events.
type RegistryCollector struct {
	keyPaths []string
	agentID  string
	host     string
	out      chan<- schema.Event
	logger   *slog.Logger
}

// NewRegistryCollector creates the collector.
func NewRegistryCollector(keyPaths []string, agentID, host string, out chan<- schema.Event, logger *slog.Logger) *RegistryCollector {
	return &RegistryCollector{
		keyPaths: keyPaths,
		agentID:  agentID,
		host:     host,
		out:      out,
		logger:   logger,
	}
}

// Run starts watchers for all configured keys and blocks until ctx is cancelled.
func (r *RegistryCollector) Run(ctx context.Context) error {
	watchers := make([]*registryWatcher, 0, len(r.keyPaths))

	for _, kp := range r.keyPaths {
		w, err := newRegistryWatcher(kp)
		if err != nil {
			r.logger.Error("registry: open key failed", "key", kp, "err", err)
			continue
		}
		if err := w.arm(); err != nil {
			r.logger.Error("registry: arm failed", "key", kp, "err", err)
			w.close()
			continue
		}
		watchers = append(watchers, w)
		r.logger.Info("registry: watching", "key", kp)
	}

	if len(watchers) == 0 {
		return fmt.Errorf("registry: no keys could be watched")
	}

	defer func() {
		for _, w := range watchers {
			w.close()
		}
	}()

	// Build a slice of event handles for WaitForMultipleObjects.
	eventHandles := make([]windows.Handle, len(watchers))
	for i, w := range watchers {
		eventHandles[i] = w.event
	}

	for {
		if ctx.Err() != nil {
			return nil
		}

		idx, err := waitForAny(eventHandles, 500) // 500ms timeout
		if err != nil {
			continue // timeout or error, loop again
		}

		w := watchers[idx]
		r.emit(w.keyPath)

		// Re-arm the watcher so it fires again on the next change.
		if err := w.arm(); err != nil {
			r.logger.Error("registry: re-arm failed", "key", w.keyPath, "err", err)
		}
	}
}

func (r *RegistryCollector) emit(keyPath string) {
	raw := rawRegEvent{
		Key:       keyPath,
		Action:    "changed",
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	rawJSON, _ := json.Marshal(raw)

	ev := schema.Event{
		Time:      time.Now().UTC(),
		AgentID:   r.agentID,
		Host:      r.host,
		OS:        "windows",
		EventType: schema.EventTypeRegistry,
		Severity:  schema.SeverityMedium,
		Source:    "RegNotify",
		RegKey:    keyPath,
		Raw:       rawJSON,
	}

	select {
	case r.out <- ev:
	default:
		r.logger.Warn("registry: out channel full, dropping event")
	}
}

// ---------------------------------------------------------------------------
// registryWatcher helpers
// ---------------------------------------------------------------------------

func newRegistryWatcher(keyPath string) (*registryWatcher, error) {
	hive, subKey, err := splitHive(keyPath)
	if err != nil {
		return nil, err
	}

	handle, err := registry.OpenKey(hive, subKey, registry.NOTIFY|registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, fmt.Errorf("OpenKey %q: %w", keyPath, err)
	}

	ev, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("CreateEvent: %w", err)
	}

	return &registryWatcher{
		keyPath: keyPath,
		hive:    hive,
		subKey:  subKey,
		handle:  handle,
		event:   ev,
	}, nil
}

// arm calls RegNotifyChangeKeyValue so the event fires on the next change.
func (w *registryWatcher) arm() error {
	ret, _, err := regNotifyChangeKeyValueProc.Call(
		uintptr(w.handle),
		1,                      // bWatchSubtree
		regNotifyFilter,
		uintptr(w.event),
		1,                      // fAsynchronous
	)
	if ret != 0 {
		return fmt.Errorf("RegNotifyChangeKeyValue: %w", err)
	}
	return nil
}

func (w *registryWatcher) close() {
	w.handle.Close()
	windows.CloseHandle(w.event)
}

var (
	modAdvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	regNotifyChangeKeyValueProc   = modAdvapi32.NewProc("RegNotifyChangeKeyValue")
)

// splitHive parses "HKLM\SOFTWARE\..." into (registry.LOCAL_MACHINE, "SOFTWARE\...").
func splitHive(keyPath string) (registry.Key, string, error) {
	parts := strings.SplitN(keyPath, `\`, 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid key path %q", keyPath)
	}
	var hive registry.Key
	switch strings.ToUpper(parts[0]) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		hive = registry.LOCAL_MACHINE
	case "HKCU", "HKEY_CURRENT_USER":
		hive = registry.CURRENT_USER
	case "HKCR", "HKEY_CLASSES_ROOT":
		hive = registry.CLASSES_ROOT
	case "HKU", "HKEY_USERS":
		hive = registry.USERS
	default:
		return 0, "", fmt.Errorf("unknown hive %q", parts[0])
	}
	return hive, parts[1], nil
}

// waitForAny calls WaitForMultipleObjects and returns the signalled index.
func waitForAny(handles []windows.Handle, timeoutMs uint32) (int, error) {
	if len(handles) == 0 {
		return 0, fmt.Errorf("no handles")
	}
	ret, err := windows.WaitForMultipleObjects(handles, false, timeoutMs)
	const waitObject0 = 0x00000000
	const waitTimeout = 0x00000102
	if ret == waitTimeout {
		return 0, fmt.Errorf("timeout")
	}
	if ret == 0xFFFFFFFF {
		return 0, err
	}
	return int(ret - waitObject0), nil
}

// Silence the "unsafe" import if not used directly in this file.
var _ = unsafe.Pointer(nil)
