# OpenSIEM Agent

A lightweight, open-source Windows security event collection agent written in Go. It collects security telemetry from Windows hosts and forwards it to a centralized backend for storage and analysis.

> **Status:** v0.1.0 — agent + forwarder complete. Backend and frontend are in active development.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Installation](#installation)
- [Configuration](#configuration)
- [TLS & Authentication](#tls--authentication)
- [Running the Agent](#running-the-agent)
- [Offline Buffering](#offline-buffering)
- [Collected Event Types](#collected-event-types)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The OpenSIEM agent runs as a Windows Service on each host you want to monitor. It collects events from five sources, normalizes them into a common schema, and forwards them over HTTPS to the backend ingest API in batches.

**Key properties:**

- Single `.exe` binary — no runtime or installer dependencies
- Runs as a native Windows Service (auto-starts on boot)
- Supports **mTLS** (mutual TLS) or **API key** authentication to the backend
- **Durable offline queue** — events are buffered to disk and retried if the backend is unreachable
- Zero external runtime dependencies — only two Go modules required (`golang.org/x/sys`, `gopkg.in/yaml.v3`)

---

## Architecture

```
Windows Host
┌──────────────────────────────────────────────┐
│                                              │
│  Collectors                                  │
│  ┌───────────┐  ┌────────┐  ┌──────────┐    │
│  │ EventLog  │  │ Sysmon │  │ Network  │    │
│  └─────┬─────┘  └───┬────┘  └────┬─────┘    │
│        │            │            │           │
│  ┌─────┴─────┐  ┌───┴────┐       │           │
│  │ Registry  │  │Process │       │           │
│  └─────┬─────┘  └───┬────┘       │           │
│        └────────────┴────────────┘           │
│                     │                        │
│              event channel                   │
│                     │                        │
│             ┌───────▼────────┐               │
│             │  Normalizer /  │               │
│             │    Enricher    │               │
│             └───────┬────────┘               │
│                     │                        │
│             ┌───────▼────────┐               │
│             │  Disk Queue    │               │
│             │ (JSONL files)  │               │
│             └───────┬────────┘               │
│                     │                        │
│             ┌───────▼────────┐               │
│             │ HTTP Forwarder │──────────────► Backend API
│             │  (mTLS/HTTPS)  │   POST /api/v1/events
│             └────────────────┘               │
└──────────────────────────────────────────────┘
```

Events flow: **Collectors → Channel → Normalizer/Enricher → Disk Queue → HTTP Forwarder → Backend**

The disk queue decouples collection from delivery — if the backend goes offline, events accumulate locally and are sent when the connection is restored.

---

## Prerequisites

### To build

- [Go 1.22+](https://go.dev/dl/) installed on any OS (cross-compilation to Windows works from Linux/macOS)
- Git

### To run

- Windows 10 / Windows Server 2016 or later (64-bit)
- Administrator privileges (required for Event Log access, service installation, and registry watching)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) installed on the host if `collector.sysmon.enabled: true` (optional but recommended)
- Network access from the host to the backend ingest URL

---

## Building

### Quick build (from Windows)

```powershell
git clone https://github.com/YOUR_ORG/opensiem.git
cd opensiem/agent
go mod tidy
go build -o agent.exe ./cmd/agent
```

### Cross-compile from Linux or macOS

```bash
git clone https://github.com/YOUR_ORG/opensiem.git
cd opensiem/agent
go mod tidy
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
```

### Build with version info embedded

```bash
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-X main.version=0.1.0 -s -w" \
  -o agent.exe ./cmd/agent
```

The `-s -w` flags strip debug info and reduce binary size.

---

## Installation

### Option 1 — PowerShell installer (recommended)

Copy `agent.exe` and `install.ps1` to the target host, then run from an elevated PowerShell prompt:

```powershell
# Install with a specific backend URL
.\install.ps1 -Action install -BackendURL "https://siem.yourcompany.com:8443"

# Install with a custom agent ID
.\install.ps1 -Action install -BackendURL "https://siem.yourcompany.com:8443" -AgentID "workstation-01"

# Install and generate a self-signed dev certificate
.\install.ps1 -Action install -BackendURL "https://siem.yourcompany.com:8443" -GenerateCert

# Check service status
.\install.ps1 -Action status

# Update binary only (stops service, replaces .exe, restarts)
.\install.ps1 -Action update

# Remove the service
.\install.ps1 -Action uninstall
```

The installer will:
1. Create `C:\Program Files\OpenSIEM\Agent\` and `C:\ProgramData\OpenSIEM\`
2. Copy `agent.exe` to the install directory
3. Write `agent.yaml` with your backend URL
4. Register the service with the Windows SCM (auto-start on boot)
5. Configure 3-strike restart recovery
6. Start the service immediately

### Option 2 — Manual install

```powershell
# 1. Copy files
New-Item -ItemType Directory -Path "C:\Program Files\OpenSIEM\Agent"
Copy-Item agent.exe "C:\Program Files\OpenSIEM\Agent\"
Copy-Item configs\agent.yaml "C:\Program Files\OpenSIEM\Agent\"

# 2. Create data directory
New-Item -ItemType Directory -Path "C:\ProgramData\OpenSIEM"

# 3. Edit agent.yaml — set backend_url at minimum (see Configuration section)

# 4. Register and start service (run as Administrator)
& "C:\Program Files\OpenSIEM\Agent\agent.exe" -config "C:\Program Files\OpenSIEM\Agent\agent.yaml" install
Start-Service OpenSIEMAgent
```

---

## Configuration

The agent is configured by a single YAML file. By default it looks for `agent.yaml` in the current directory. Override with the `-config` flag.

### Full annotated `agent.yaml`

```yaml
agent:
  # Unique identifier for this agent instance.
  # Leave empty to use the machine hostname (recommended).
  id: ""
  version: "0.1.0"

collector:
  event_log:
    enabled: true
    # Windows Event Log channels to subscribe to.
    # Add any valid channel name (run: wevtutil el to list all).
    channels:
      - Security
      - System
      - Application
      - Microsoft-Windows-PowerShell/Operational
    # How often to poll for new events.
    poll_interval: 5s

  sysmon:
    # Requires Sysmon to be installed separately on the host.
    # https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    enabled: true

  network:
    enabled: true
    # How often to snapshot TCP connection table and emit deltas.
    poll_interval: 30s

  process:
    # ETW (Event Tracing for Windows) real-time process events.
    enabled: true

  registry:
    enabled: true
    # Registry keys to watch for any change (key creation, deletion, value changes).
    # Use HKLM, HKCU, HKCR, or HKU prefixes.
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - HKLM\SYSTEM\CurrentControlSet\Services
      - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

forwarder:
  # Full URL of the backend ingest API. Must include scheme and port.
  backend_url: "https://siem.yourcompany.com:8443"

  # How many events to bundle into a single HTTP POST.
  batch_size: 200

  # Send a batch at this interval even if batch_size is not reached.
  flush_interval: 5s

  # --- mTLS (recommended for production) ---
  # Paths are relative to agent.yaml location, or use absolute paths.
  cert_file: "certs/agent.crt"   # Agent's client certificate (PEM)
  key_file:  "certs/agent.key"   # Agent's private key (PEM)
  ca_file:   "certs/ca.crt"      # CA that signed the backend's server cert (PEM)

  # --- API key (simpler, use if not using mTLS) ---
  # Comment out cert_file/key_file/ca_file above and uncomment this:
  # api_key: "your-secret-key-here"

queue:
  # Directory where the offline event buffer is stored.
  # The agent creates a segments/ subfolder here automatically.
  db_path: "C:\\ProgramData\\OpenSIEM\\queue"
  # Maximum number of buffered events before oldest are evicted.
  max_rows: 100000

log:
  level: "info"    # debug | info | warn | error
  format: "json"   # json  | text
```

### Minimal config (API key auth, no mTLS)

```yaml
agent:
  id: ""
  version: "0.1.0"

collector:
  event_log:
    enabled: true
    channels: [Security, System, Application]
    poll_interval: 5s
  sysmon:
    enabled: false
  network:
    enabled: true
    poll_interval: 30s
  process:
    enabled: true
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  batch_size: 200
  flush_interval: 5s
  api_key: "your-secret-key-here"

queue:
  db_path: "C:\\ProgramData\\OpenSIEM\\queue"
  max_rows: 100000

log:
  level: "info"
  format: "json"
```

---

## TLS & Authentication

The agent supports two transport authentication modes. You must configure one of them — the backend will reject unauthenticated requests.

### Mode 1 — Mutual TLS (mTLS) — Recommended for Production

With mTLS, both the agent (client) and the backend (server) present certificates. This means:

- The agent verifies the backend is legitimate (prevents sending data to a fake server)
- The backend verifies the agent is enrolled (prevents rogue agents from injecting events)

#### Step 1 — Create a Certificate Authority (do this once on the backend server)

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate self-signed CA certificate (valid 10 years)
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/O=OpenSIEM/CN=OpenSIEM-CA"
```

Keep `ca.key` private and secure. `ca.crt` is distributed to all agents.

#### Step 2 — Create the backend server certificate (do this once)

```bash
# Generate backend private key
openssl genrsa -out server.key 2048

# Generate CSR
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/O=OpenSIEM/CN=siem.yourcompany.com"

# Sign with your CA — include the backend's hostname/IP in the SAN
cat > server-ext.cnf << EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = siem.yourcompany.com
IP.1  = 192.168.1.100
EOF

openssl x509 -req -days 825 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -extfile server-ext.cnf -extensions v3_req
```

Install `server.crt` and `server.key` on the backend server.

#### Step 3 — Create a certificate for each agent

```bash
# Replace HOSTNAME with the actual machine name
HOSTNAME="workstation-01"

openssl genrsa -out ${HOSTNAME}.key 2048

openssl req -new -key ${HOSTNAME}.key -out ${HOSTNAME}.csr \
  -subj "/C=US/O=OpenSIEM/CN=${HOSTNAME}"

openssl x509 -req -days 825 -in ${HOSTNAME}.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out ${HOSTNAME}.crt
```

#### Step 4 — Deploy certs to the agent host

Copy these three files to `C:\Program Files\OpenSIEM\Agent\certs\` on the Windows host:

| File | What it is |
|---|---|
| `agent.crt` | The agent's client certificate (rename from `HOSTNAME.crt`) |
| `agent.key` | The agent's private key (rename from `HOSTNAME.key`) |
| `ca.crt` | Your CA certificate — used to verify the backend |

#### Step 5 — Update `agent.yaml`

```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  cert_file: "certs/agent.crt"
  key_file:  "certs/agent.key"
  ca_file:   "certs/ca.crt"
```

Paths are relative to the location of `agent.yaml`. You can also use absolute paths:

```yaml
  cert_file: "C:\\Program Files\\OpenSIEM\\Agent\\certs\\agent.crt"
  key_file:  "C:\\Program Files\\OpenSIEM\\Agent\\certs\\agent.key"
  ca_file:   "C:\\Program Files\\OpenSIEM\\Agent\\certs\\ca.crt"
```

---

### Mode 2 — API Key Authentication (Simpler)

If you don't want to manage certificates, use API key auth instead. Remove or comment out the `cert_file`, `key_file`, and `ca_file` fields and set `api_key`:

```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  api_key: "your-secret-key-here"
```

The agent will include this in every request as the `X-API-Key` HTTP header. The backend must validate this header.

> **Note:** API key auth still requires HTTPS. Do not use `http://` in `backend_url` — your events and API key would be transmitted in plaintext.

---

### Reaching the Backend — Network Requirements

| Source | Destination | Port | Protocol |
|---|---|---|---|
| Windows host (agent) | Backend ingest server | 8443 (default) | HTTPS / HTTP/2 |

If the host is behind a firewall, ensure outbound TCP port 8443 is open to the backend IP/hostname. The port is configurable — whatever port is in `backend_url` is what the agent connects to.

**No inbound ports are needed on the Windows host** — the agent only makes outbound connections.

#### DNS resolution

Make sure the backend hostname in `backend_url` resolves from the Windows host:

```powershell
# Test from the Windows host
Resolve-DnsName siem.yourcompany.com

# Test connectivity
Test-NetConnection -ComputerName siem.yourcompany.com -Port 8443
```

#### Testing the connection manually

```powershell
# Should return HTTP 200 or 401, not a connection error
Invoke-WebRequest -Uri "https://siem.yourcompany.com:8443/api/v1/health" -SkipCertificateCheck
```

---

## Running the Agent

### As a Windows Service (normal operation)

After installation the service runs automatically. To manage it:

```powershell
# Check status
Get-Service OpenSIEMAgent

# Start / stop / restart
Start-Service OpenSIEMAgent
Stop-Service OpenSIEMAgent
Restart-Service OpenSIEMAgent

# View recent logs (Windows Event Log)
Get-EventLog -LogName Application -Source OpenSIEMAgent -Newest 50
```

### Interactively (for testing and debugging)

Run directly in a PowerShell terminal — logs print to stdout. Press `Ctrl+C` to stop.

```powershell
# Run with default config
.\agent.exe -config agent.yaml

# Run with debug logging
# Edit agent.yaml: log.level = "debug"
.\agent.exe -config agent.yaml
```

### Service management commands

```powershell
# Install service (must be run as Administrator)
.\agent.exe -config "C:\Program Files\OpenSIEM\Agent\agent.yaml" install

# Remove service
.\agent.exe uninstall
```

---

## Offline Buffering

The agent uses a durable disk queue to prevent event loss when the backend is unreachable (network outage, backend restart, etc.).

**How it works:**

1. Events are written to JSONL segment files in `queue.db_path/segments/`
2. The HTTP forwarder reads from the queue and posts to the backend
3. If a POST fails, events are re-queued and retried with exponential backoff
4. If `max_rows` is exceeded, the oldest events are evicted (ring buffer)

**Retry schedule** (exponential backoff with full jitter):

| Attempt | Max wait before retry |
|---|---|
| 1 | ~500ms |
| 2 | ~1s |
| 3 | ~2s |
| 4 | ~4s |
| 5 | ~8s |
| 6 | ~16s |
| 7 | ~32s |
| 8 (final) | fail, re-queue |

**Inspecting the queue:**

The queue files are plain text and human-readable:

```powershell
# See how many segment files exist
Get-ChildItem "C:\ProgramData\OpenSIEM\queue\segments\"

# Read a segment (each line is one JSON event)
Get-Content "C:\ProgramData\OpenSIEM\queue\segments\0000000001.jsonl" | 
  ConvertFrom-Json | Select-Object time, event_type, host | Format-Table
```

---

## Collected Event Types

| Type | Source | What it captures |
|---|---|---|
| `logon` | Windows Security log | Successful/failed logons (4624, 4625), admin logons (4672), explicit credentials (4648) |
| `process` | Windows Security log + ETW | Process creation (4688) and termination (4689), command lines |
| `network` | `iphlpapi.dll` snapshot | TCP connect/disconnect events with PID, src/dst IP and port |
| `file` | Windows Security log | Object access (4663), file creation/deletion via Sysmon |
| `registry` | `RegNotifyChangeKeyValue` | Changes to watched registry keys — creation, deletion, value modification |
| `sysmon` | Sysmon Operational log | 17 high-value Sysmon event IDs — see table below |
| `raw` | All channels | Any event not classified by the above rules |

### Sysmon Event ID coverage

| ID | Name | Severity |
|---|---|---|
| 1 | ProcessCreate | Low |
| 3 | NetworkConnect | Low |
| 5 | ProcessTerminate | Info |
| 6 | DriverLoad | **High** |
| 7 | ImageLoad | Low |
| 8 | CreateRemoteThread | **High** |
| 9 | RawAccessRead | **High** |
| 10 | ProcessAccess | Medium |
| 11 | FileCreate | Low |
| 12 | RegistryCreate | Low |
| 13 | RegistrySetValue | Medium |
| 14 | RegistryRename | Medium |
| 15 | FileCreateStreamHash | Medium |
| 17 | PipeCreated | Low |
| 18 | PipeConnected | Low |
| 22 | DNSQuery | Low |
| 23 | FileDeleteDetected | Medium |

### Severity scale

| Value | Label | Meaning |
|---|---|---|
| 1 | Info | Routine — logoff, process exit |
| 2 | Low | Normal activity — new connection, file create |
| 3 | Medium | Worth reviewing — failed logon, registry change |
| 4 | High | Investigate promptly — remote thread, driver load, account created |
| 5 | Critical | Immediate attention — Windows Critical level events |

---

## Project Structure

```
agent/
├── cmd/
│   └── agent/
│       └── main.go           # Entry point; Windows service registration
├── internal/
│   ├── collector/
│   │   ├── eventlog.go       # Subscribes to Windows Event Log channels (wevtapi.dll)
│   │   ├── sysmon.go         # Reads Microsoft-Windows-Sysmon/Operational channel
│   │   ├── network.go        # Snapshots TCP table via iphlpapi.dll, emits deltas
│   │   ├── process.go        # ETW Kernel-Process provider (process start/stop)
│   │   └── registry.go       # Watches registry keys via RegNotifyChangeKeyValue
│   ├── parser/
│   │   ├── normalizer.go     # Validates + classifies events; maps EventIDs to types
│   │   └── enricher.go       # Stamps agent ID, hostname, deterministic dedup ID
│   ├── forwarder/
│   │   ├── http.go           # HTTP/2 + mTLS batch forwarder
│   │   ├── queue.go          # Durable JSONL segment queue (stdlib only)
│   │   └── retry.go          # Exponential backoff with full jitter
│   └── config/
│       └── config.go         # YAML config loader with defaults and validation
├── pkg/
│   └── schema/
│       └── event.go          # Shared Event and Batch types (JSON schema)
├── configs/
│   └── agent.yaml            # Default configuration template
├── build/
│   └── windows/
│       └── install.ps1       # PowerShell service installer
└── go.mod
```

---

## Contributing

Contributions are welcome! Please open an issue before submitting a large PR so we can discuss the approach.

**Good first issues:**
- Complete the ETW process collector (`process.go` has the structure stubbed out — full Win32 interop needed)
- Add XML parsing in `eventlog.go` to extract structured fields from the raw XML payload
- Add a `--dry-run` flag that prints events to stdout instead of forwarding
- Write unit tests for the normalizer and enricher
- Add a Sysmon configuration template (`sysmon-config.xml`) to the repo

**Development setup:**

```bash
git clone https://github.com/YOUR_ORG/opensiem.git
cd opensiem/agent
go mod tidy

# Run tests
go test ./...

# Build for Windows from Linux/Mac
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
