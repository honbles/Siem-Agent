//go:build windows

package sysmon

// installer.go — automatically detects and installs Sysmon if not present.
//
// Two modes:
//   1. Embedded binary (build with -tags embed_sysmon):
//      Place Sysmon64.exe in agent/internal/sysmon/embed/Sysmon64.exe
//      before building. The binary is compiled into the agent exe.
//
//   2. Download mode (default):
//      Downloads Sysmon.zip from Microsoft Sysinternals and installs silently.
//
// Sysmon is installed with a minimal config that captures:
//   - Process creation with command line (Event ID 1)
//   - Network connections (Event ID 3)
//   - File creation (Event ID 11)
//   - Registry events (Event IDs 12, 13)
//   - DNS queries (Event ID 22)

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	sysmonDownloadURL = "https://download.sysinternals.com/files/Sysmon.zip"
	sysmonInstallDir  = `C:\Windows\System32`
	sysmonConfigName  = "sysmon-config.xml"
)

// Minimal Sysmon config — captures the events ObsidianWatch needs
// without generating noise from every routine system call.
const sysmonConfig = `<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>

    <!-- Event ID 1 — Process Create (with command line) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <!-- Exclude noisy system processes -->
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <Image condition="is">C:\Windows\System32\WerFault.exe</Image>
        <Image condition="is">C:\Windows\System32\conhost.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3 — Network Connect -->
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <!-- Exclude Windows update noise -->
        <Image condition="is">C:\Windows\System32\svchost.exe</Image>
        <DestinationPort condition="is">137</DestinationPort>
        <DestinationPort condition="is">138</DestinationPort>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 7 — Image/DLL Load -->
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <Image condition="contains">powershell</Image>
        <Image condition="contains">cmd.exe</Image>
        <Image condition="contains">mshta</Image>
        <Image condition="contains">wscript</Image>
        <Image condition="contains">cscript</Image>
      </ImageLoad>
    </RuleGroup>

    <!-- Event ID 10 — Process Access (LSASS dumps) -->
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <TargetImage condition="contains">lsass.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>

    <!-- Event ID 11 — File Create -->
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">\Temp\</TargetFilename>
        <TargetFilename condition="contains">\AppData\</TargetFilename>
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.ps1</TargetFilename>
        <TargetFilename condition="end with">.bat</TargetFilename>
        <TargetFilename condition="end with">.vbs</TargetFilename>
        <TargetFilename condition="end with">.dll</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <!-- Event ID 12/13 — Registry -->
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        <TargetObject condition="contains">Policies\Explorer\Run</TargetObject>
        <TargetObject condition="contains">CurrentVersion\Winlogon</TargetObject>
        <TargetObject condition="contains">AppInit_DLLs</TargetObject>
      </RegistryEvent>
    </RuleGroup>

    <!-- Event ID 22 — DNS Query -->
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <!-- Exclude Windows internal DNS noise -->
        <QueryName condition="end with">.microsoft.com</QueryName>
        <QueryName condition="end with">.windowsupdate.com</QueryName>
        <QueryName condition="end with">.windows.com</QueryName>
      </DnsQuery>
    </RuleGroup>

  </EventFiltering>
</Sysmon>`

// Status represents the current Sysmon installation state.
type Status int

const (
	StatusNotInstalled Status = iota
	StatusInstalled
	StatusRunning
)

// Check returns the current Sysmon status without modifying anything.
func Check() Status {
	m, err := mgr.Connect()
	if err != nil {
		return StatusNotInstalled
	}
	defer m.Disconnect()

	for _, name := range []string{"Sysmon64", "Sysmon", "SysmonDrv"} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		defer s.Close()
		status, err := s.Query()
		if err != nil {
			return StatusInstalled
		}
		if status.State == 4 { // SERVICE_RUNNING
			return StatusRunning
		}
		return StatusInstalled
	}
	return StatusNotInstalled
}

// EnsureInstalled checks if Sysmon is installed and running.
// If not, it installs and starts it automatically.
// Returns true if Sysmon is running after this call.
func EnsureInstalled(logger *slog.Logger) bool {
	status := Check()

	switch status {
	case StatusRunning:
		logger.Info("sysmon: already installed and running")
		return true

	case StatusInstalled:
		logger.Info("sysmon: installed but not running — starting")
		if err := startService(logger); err != nil {
			logger.Warn("sysmon: failed to start service", "err", err)
			return false
		}
		logger.Info("sysmon: service started")
		return true

	case StatusNotInstalled:
		logger.Info("sysmon: not installed — installing automatically")
		if err := install(logger); err != nil {
			logger.Warn("sysmon: auto-install failed", "err", err)
			return false
		}
		logger.Info("sysmon: installed and running successfully ✓")
		return true
	}
	return false
}

// install downloads (or extracts embedded) Sysmon and installs it.
func install(logger *slog.Logger) error {
	// Get the Sysmon binary
	sysmonExe, tempDir, err := getSysmonBinary(logger)
	if tempDir != "" {
		defer os.RemoveAll(tempDir)
	}
	if err != nil {
		return fmt.Errorf("get binary: %w", err)
	}

	// Write the config file
	configPath := filepath.Join(os.TempDir(), sysmonConfigName)
	if err := os.WriteFile(configPath, []byte(sysmonConfig), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer os.Remove(configPath)

	// Install: Sysmon64.exe -accepteula -i <config>
	logger.Info("sysmon: running installer", "binary", sysmonExe)
	cmd := exec.Command(sysmonExe, "-accepteula", "-i", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("install failed: %w\noutput: %s", err, string(out))
	}
	logger.Info("sysmon: installation output", "output", strings.TrimSpace(string(out)))

	// Wait for service to appear
	for i := 0; i < 10; i++ {
		time.Sleep(500 * time.Millisecond)
		if Check() == StatusRunning {
			return nil
		}
	}
	// Try starting manually if not yet running
	return startService(logger)
}

// getSysmonBinary returns the path to Sysmon64.exe.
// Uses embedded binary if built with -tags embed_sysmon,
// otherwise downloads from Microsoft.
func getSysmonBinary(logger *slog.Logger) (exePath string, tempDir string, err error) {
	// Check if embedded binary is available
	if data := getEmbeddedSysmon(); data != nil {
		logger.Info("sysmon: using embedded binary")
		dir, err := os.MkdirTemp("", "obsidianwatch-sysmon-*")
		if err != nil {
			return "", "", err
		}
		exePath = filepath.Join(dir, "Sysmon64.exe")
		if err := os.WriteFile(exePath, data, 0755); err != nil {
			os.RemoveAll(dir)
			return "", "", err
		}
		return exePath, dir, nil
	}

	// Download from Microsoft
	logger.Info("sysmon: downloading from Microsoft Sysinternals", "url", sysmonDownloadURL)
	return downloadSysmon(logger)
}

// downloadSysmon downloads and extracts Sysmon64.exe from the Sysinternals zip.
func downloadSysmon(logger *slog.Logger) (exePath string, tempDir string, err error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(sysmonDownloadURL)
	if err != nil {
		return "", "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read body: %w", err)
	}
	logger.Info("sysmon: downloaded", "bytes", len(data))

	// Extract Sysmon64.exe from the zip
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", "", fmt.Errorf("open zip: %w", err)
	}

	dir, err := os.MkdirTemp("", "obsidianwatch-sysmon-*")
	if err != nil {
		return "", "", err
	}

	for _, f := range zr.File {
		if strings.EqualFold(f.Name, "Sysmon64.exe") {
			rc, err := f.Open()
			if err != nil {
				os.RemoveAll(dir)
				return "", "", fmt.Errorf("extract: %w", err)
			}
			exePath = filepath.Join(dir, "Sysmon64.exe")
			out, err := os.Create(exePath)
			if err != nil {
				rc.Close()
				os.RemoveAll(dir)
				return "", "", err
			}
			_, err = io.Copy(out, rc)
			out.Close()
			rc.Close()
			if err != nil {
				os.RemoveAll(dir)
				return "", "", fmt.Errorf("write exe: %w", err)
			}
			logger.Info("sysmon: extracted Sysmon64.exe")
			return exePath, dir, nil
		}
	}
	os.RemoveAll(dir)
	return "", "", fmt.Errorf("Sysmon64.exe not found in zip")
}

// startService starts the Sysmon service if it exists but isn't running.
func startService(logger *slog.Logger) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	for _, name := range []string{"Sysmon64", "Sysmon"} {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		defer s.Close()
		status, err := s.Query()
		if err != nil {
			continue
		}
		if status.State == 4 { // already running
			return nil
		}
		if err := s.Start(); err != nil {
			return fmt.Errorf("start %s: %w", name, err)
		}
		// Wait up to 5s for it to start
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
			st, err := s.Query()
			if err == nil && st.State == 4 {
				return nil
			}
		}
		return fmt.Errorf("service did not reach running state")
	}
	return fmt.Errorf("service not found")
}

// isAdmin checks if the current process has administrator privileges.
func IsAdmin() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()

	var isElevated uint32
	var returnLen uint32
	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&isElevated)),
		uint32(unsafe.Sizeof(isElevated)),
		&returnLen,
	)
	return err == nil && isElevated != 0
}
