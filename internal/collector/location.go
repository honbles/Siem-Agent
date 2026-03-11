//go:build windows

package collector

// location.go — Windows location collector.
//
// Uses the Windows Location API (Windows.Devices.Geolocation) via WinRT/COM.
// This is the same API that Windows Maps, Weather, and other apps use.
//
// Location sources (in order of accuracy):
//   1. GPS chip (if present) — metre-level accuracy
//   2. WiFi positioning — triangulates from nearby APs — ~50-300m accuracy
//   3. IP geolocation fallback — city-level, ~5-50km accuracy
//
// The Windows Location API requires the user/service to have location
// permission enabled. When running as SYSTEM (service), it uses the
// device's last known position from the location cache.
//
// If Windows Location API is unavailable (disabled, no permission),
// falls back to IP geolocation via ip-api.com.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"crypto/tls"
	"crypto/x509"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"obsidianwatch/agent/pkg/schema"
)

// ── Location Collector ────────────────────────────────────────────────────────

type LocationCollector struct {
	interval   time.Duration
	agentID    string
	hostname   string
	backendURL string
	apiKey     string
	caFile     string
	out        chan<- schema.Event
	logger     *slog.Logger
}

func NewLocationCollector(interval time.Duration, agentID, hostname, backendURL, apiKey, caFile string, out chan<- schema.Event, logger *slog.Logger) *LocationCollector {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &LocationCollector{
		interval:   interval,
		agentID:    agentID,
		hostname:   hostname,
		backendURL: backendURL,
		apiKey:     apiKey,
		caFile:     caFile,
		out:        out,
		logger:     logger,
	}
}

func (c *LocationCollector) Run(ctx context.Context) error {
	c.logger.Info("location: collector started", "interval", c.interval)

	// Run immediately on start, then on interval
	c.collect(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

type locationResult struct {
	Lat      float64
	Lng      float64
	Accuracy float64 // metres
	Source   string  // "gps" | "wifi" | "ip"
	City     string
	Country  string
}

func (c *LocationCollector) collect(ctx context.Context) {
	loc, err := c.getWindowsLocation(ctx)
	if err != nil {
		c.logger.Debug("location: Windows API unavailable, trying IP fallback", "err", err)
		loc, err = getIPGeolocation(ctx)
		if err != nil {
			c.logger.Warn("location: all location methods failed", "err", err)
			return
		}
	}

	c.logger.Info("location: acquired",
		"lat", fmt.Sprintf("%.4f", loc.Lat),
		"lng", fmt.Sprintf("%.4f", loc.Lng),
		"accuracy_m", loc.Accuracy,
		"source", loc.Source,
		"city", loc.City,
	)

	// Post to management server directly (location is metadata, not an event)
	if c.backendURL != "" {
		go c.postLocation(loc)
	}

	// Also emit as an event so it appears in the event stream
	raw, _ := json.Marshal(map[string]interface{}{
		"lat":      loc.Lat,
		"lng":      loc.Lng,
		"accuracy": loc.Accuracy,
		"source":   loc.Source,
		"city":     loc.City,
		"country":  loc.Country,
	})

	ev := schema.Event{
		ID:        newLocationID(),
		Time:      time.Now().UTC(),
		AgentID:   c.agentID,
		Host:      c.hostname,
		OS:        "windows",
		EventType: schema.EventTypeLocation,
		Severity:  1,
		Source:    "location/" + loc.Source,
		Raw:       raw,
	}
	select {
	case c.out <- ev:
	default:
	}
}

func (c *LocationCollector) buildHTTPClient() *http.Client {
	tlsCfg := &tls.Config{}
	if c.caFile != "" {
		caCert, err := os.ReadFile(c.caFile)
		if err == nil {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			tlsCfg.RootCAs = pool
		}
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

func (c *LocationCollector) postLocation(loc locationResult) {
	backend := strings.TrimRight(c.backendURL, "/")
	body, _ := json.Marshal(map[string]interface{}{
		"agent_id": c.agentID,
		"lat":      loc.Lat,
		"lng":      loc.Lng,
		"accuracy": loc.Accuracy,
		"source":   loc.Source,
		"city":     loc.City,
		"country":  loc.Country,
	})
	client := c.buildHTTPClient()
	req, err := http.NewRequest("POST", backend+"/api/v1/agents/location", strings.NewReader(string(body)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	resp, err := client.Do(req)
	if err != nil {
		c.logger.Debug("location: post failed", "err", err)
		return
	}
	resp.Body.Close()
}

// ── Windows Location API ──────────────────────────────────────────────────────
//
// We use the ILocation COM interface (Windows Vista+) which is simpler than
// WinRT and works in service context without a message pump.
// ILocation CLSID: {E5B8E079-EE6D-4E33-A438-C87F2E959254}
// ILocation IID:   {AB2BC69E-CE13-456E-A1B6-876052B4E8F3}

var (
	CLSID_Location = windows.GUID{
		Data1: 0xE5B8E079,
		Data2: 0xEE6D,
		Data3: 0x4E33,
		Data4: [8]byte{0xA4, 0x38, 0xC8, 0x7F, 0x2E, 0x95, 0x92, 0x54},
	}
	IID_ILocation = windows.GUID{
		Data1: 0xAB2BC69E,
		Data2: 0xCE13,
		Data3: 0x456E,
		Data4: [8]byte{0xA1, 0xB6, 0x87, 0x60, 0x52, 0xB4, 0xE8, 0xF3},
	}
	IID_ILatLongReport = windows.GUID{
		Data1: 0x7FED806D,
		Data2: 0x0EF8,
		Data3: 0x4F07,
		Data4: [8]byte{0x80, 0xAC, 0x36, 0xA0, 0xBE, 0xAE, 0x31, 0x34},
	}
)

// ILocation vtable layout (simplified — only methods we need)
type iLocationVtbl struct {
	QueryInterface         uintptr
	AddRef                 uintptr
	Release                uintptr
	RegisterForReport      uintptr
	UnregisterForReport    uintptr
	GetReport              uintptr
	GetReportStatus        uintptr
	GetReportInterval      uintptr
	SetReportInterval      uintptr
	GetReportFactory       uintptr
	RequestPermissions     uintptr
}

type iLocation struct {
	vtbl *iLocationVtbl
}

func (c *LocationCollector) getWindowsLocation(ctx context.Context) (locationResult, error) {
	// Initialise COM
	ole32 := windows.NewLazySystemDLL("ole32.dll")
	coInitEx := ole32.NewProc("CoInitializeEx")
	coCreateInst := ole32.NewProc("CoCreateInstance")
	coUninit := ole32.NewProc("CoUninitialize")

	ret, _, _ := coInitEx.Call(0, 0) // COINIT_MULTITHREADED
	if ret != 0 && ret != 0x80010106 { // S_OK or RPC_E_CHANGED_MODE
		return locationResult{}, fmt.Errorf("CoInitializeEx: 0x%x", ret)
	}
	defer coUninit.Call()

	var pLoc *iLocation
	ret, _, _ = coCreateInst.Call(
		uintptr(unsafe.Pointer(&CLSID_Location)),
		0,
		0x17, // CLSCTX_ALL
		uintptr(unsafe.Pointer(&IID_ILocation)),
		uintptr(unsafe.Pointer(&pLoc)),
	)
	if ret != 0 {
		return locationResult{}, fmt.Errorf("CoCreateInstance ILocation: 0x%x", ret)
	}
	if pLoc == nil {
		return locationResult{}, fmt.Errorf("ILocation is nil")
	}
	defer syscall.SyscallN(pLoc.vtbl.Release, uintptr(unsafe.Pointer(pLoc)))

	// Request permission (non-blocking — uses cached permission)
	syscall.SyscallN(pLoc.vtbl.RequestPermissions, uintptr(unsafe.Pointer(pLoc)), 0,
		uintptr(unsafe.Pointer(&IID_ILatLongReport)), 0)

	// GetReport — synchronous, returns last cached fix
	var pReport uintptr
	ret, _, _ = syscall.SyscallN(pLoc.vtbl.GetReport,
		uintptr(unsafe.Pointer(pLoc)),
		uintptr(unsafe.Pointer(&IID_ILatLongReport)),
		uintptr(unsafe.Pointer(&pReport)),
	)
	if ret != 0 || pReport == 0 {
		return locationResult{}, fmt.Errorf("GetReport: 0x%x", ret)
	}

	// ILatLongReport vtable: QI, AddRef, Release, GetSensorID, GetTimestamp,
	// GetValue, GetLatitude (idx 6), GetLongitude (idx 7), GetErrorRadius (idx 8), GetAltitude (idx 9)
	vtbl := *(*[20]uintptr)(unsafe.Pointer(pReport))
	defer syscall.SyscallN(vtbl[2], pReport) // Release

	var lat, lng, errRadius float64
	ret, _, _ = syscall.SyscallN(vtbl[6], pReport, uintptr(unsafe.Pointer(&lat)))
	if ret != 0 {
		return locationResult{}, fmt.Errorf("GetLatitude: 0x%x", ret)
	}
	ret, _, _ = syscall.SyscallN(vtbl[7], pReport, uintptr(unsafe.Pointer(&lng)))
	if ret != 0 {
		return locationResult{}, fmt.Errorf("GetLongitude: 0x%x", ret)
	}
	syscall.SyscallN(vtbl[8], pReport, uintptr(unsafe.Pointer(&errRadius)))

	if lat == 0 && lng == 0 {
		return locationResult{}, fmt.Errorf("location returned (0,0) — no fix")
	}

	source := "wifi"
	if errRadius < 50 {
		source = "gps"
	}

	result := locationResult{
		Lat:      lat,
		Lng:      lng,
		Accuracy: errRadius,
		Source:   source,
	}

	// Reverse geocode to get city/country
	if city, country, err := reverseGeocode(ctx, lat, lng); err == nil {
		result.City = city
		result.Country = country
	}

	return result, nil
}

// ── IP Geolocation fallback ───────────────────────────────────────────────────

func getIPGeolocation(ctx context.Context) (locationResult, error) {
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://ip-api.com/json/?fields=lat,lon,city,country,status", nil)
	if err != nil {
		return locationResult{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return locationResult{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var r struct {
		Status  string  `json:"status"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		City    string  `json:"city"`
		Country string  `json:"country"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Status != "success" {
		return locationResult{}, fmt.Errorf("ip-api: %s", r.Status)
	}

	return locationResult{
		Lat:      r.Lat,
		Lng:      r.Lon,
		Accuracy: 5000, // city-level ~5km
		Source:   "ip",
		City:     r.City,
		Country:  r.Country,
	}, nil
}

// reverseGeocode converts lat/lng to city/country using nominatim (OSM).
func reverseGeocode(ctx context.Context, lat, lng float64) (city, country string, err error) {
	url := fmt.Sprintf("https://nominatim.openstreetmap.org/reverse?lat=%.6f&lon=%.6f&format=json", lat, lng)
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "ObsidianWatch-Agent/0.3.1")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var r struct {
		Address struct {
			City        string `json:"city"`
			Town        string `json:"town"`
			Village     string `json:"village"`
			CountryCode string `json:"country_code"`
			Country     string `json:"country"`
		} `json:"address"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", "", err
	}
	city = r.Address.City
	if city == "" {
		city = r.Address.Town
	}
	if city == "" {
		city = r.Address.Village
	}
	return city, r.Address.Country, nil
}

func newLocationID() string {
	return fmt.Sprintf("loc-%d", time.Now().UnixNano())
}
