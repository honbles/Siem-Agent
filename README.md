# ObsidianWatch Agent

A lightweight, open-source Windows security event collection agent written in Go. Collects security telemetry from Windows hosts and forwards it to the ObsidianWatch backend for centralized storage and analysis.

**Version: v0.2.0** — agent fully operational with 10 active collectors.

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
- [Collectors](#collectors)
- [Event Schema](#event-schema)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

The ObsidianWatch agent runs as a Windows Service on each host you want to monitor. It collects events from **ten independent sources**, normalises them into a common schema, rate-limits and deduplicates them, then forwards them over HTTPS to the backend ingest API in batches.

**What the agent does:**

- Parses every Windows Event Log entry into structured fields — user, domain, PID, process name, command line, IPs, ports, registry keys — extracted from the raw XML, not stored as a blob
- Monitors process start and stop in real time via ETW, with automatic WMI polling fallback
- Captures DNS queries and responses without requiring Sysmon, using the built-in Windows DNS-Client provider
- Watches critical directories for file create, modify, delete, and rename events via `ReadDirectoryChangesW`
- Tails any application log file and ships each new line — JSON fields auto-extracted, Apache/nginx combined format parsed automatically
- Detects registry changes on high-value keys the moment they happen
- Emits agent health heartbeats every 60 seconds so the backend always knows the agent is alive
- Buffers all events to a durable disk queue and retries with exponential backoff if the backend is unreachable
- Rate-limits and deduplicates per source to prevent log floods from filling the queue

**Key properties:**

- Single `.exe` binary — no runtime, no installer dependencies
- Runs as a native Windows Service (auto-starts on boot)
- mTLS or API key authentication
- Zero data loss — durable disk queue survives agent and backend restarts
- All collectors are independently enable/disable via `agent.yaml`

---

## Architecture

```
Windows Host
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Collectors                                                 │
│  ┌──────────┐ ┌────────┐ ┌─────────┐ ┌──────────────────┐  │
│  │EventLog  │ │Sysmon  │ │Network  │ │     Process      │  │
│  │Full XML  │ │17 IDs  │ │TCP diff │ │  ETW / WMI poll  │  │
│  │field     │ │mapped  │ │iphlpapi │ │  fallback        │  │
│  │extract   │ │        │ │         │ │                  │  │
│  └────┬─────┘ └───┬────┘ └────┬────┘ └────────┬─────────┘  │
│       │           │           │               │             │
│  ┌────┴────┐ ┌────┴───┐ ┌─────┴────┐ ┌────────┴────────┐   │
│  │Registry │ │  DNS   │ │   FIM    │ │     AppLog      │   │
│  │RegNotify│ │DNS-    │ │ReadDir   │ │ tail any file   │   │
│  │Change   │ │Client/ │ │Changes W │ │ json/text/      │   │
│  │KeyValue │ │Operat. │ │          │ │ combined        │   │
│  └────┬────┘ └────┬───┘ └─────┬────┘ └────────┬────────┘   │
│       │           │           │               │             │
│       └───────────┴─────┬─────┴───────────────┘             │
│                         │                                   │
│              ┌──────────▼──────────┐                        │
│              │   Rate Limiter /    │  500 evt/s per source  │
│              │   Deduplicator      │  5s dedupe window      │
│              └──────────┬──────────┘                        │
│                         │                                   │
│              ┌──────────▼──────────┐                        │
│              │  Normalizer /       │  field hygiene,        │
│              │  Enricher           │  EventID → type/sev    │
│              └──────────┬──────────┘                        │
│                         │                                   │
│              ┌──────────▼──────────┐                        │
│              │  Disk Queue         │  JSONL segment files   │
│              │                     │  survives restarts     │
│              └──────────┬──────────┘                        │
│                         │                                   │
│              ┌──────────▼──────────┐                        │
│              │  HTTP Forwarder     │──────────► Backend API │
│              │  mTLS / API key     │  POST /api/v1/events   │
│              └─────────────────────┘                        │
│                                                             │
│  Health Reporter ─────────────────────────────────────────► │
│  60s heartbeat: queue depth, drops, memory, goroutines      │
└─────────────────────────────────────────────────────────────┘
```

**Event pipeline:** Collectors → Rate Limiter → Normalizer/Enricher → Disk Queue → HTTP Forwarder → Backend

---

## Prerequisites

**To build:**
- Go 1.22+
- Git

**To run:**
- Windows 10 / Windows Server 2016 or later (64-bit)
- Administrator privileges (required for Event Log, ETW, service install, registry watching, FIM)
- Sysmon installed only if `collector.sysmon.enabled: true` — all other collectors work without it
- Outbound HTTPS access from the host to the backend ingest URL

---

## Building

**From Windows:**
```powershell
git clone https://github.com/honbles/Seim-Agent.git
cd Siem-Agent
go mod tidy
go build -o agent.exe ./cmd/agent
```

**Cross-compile from Linux / macOS:**
```bash
git clone https://github.com/honbles/Seim-Agent.git
cd Siem-Agent
go mod tidy
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
```

**With version info embedded:**
```bash
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-X main.version=0.2.0 -s -w" \
  -o agent.exe ./cmd/agent
```

---

## Installation

**Install as a Windows Service (run as Administrator):**

```powershell
# 1. Register the service
.\agent.exe -config "C:\Program Files\ObsidianWatch\Agent\agent.yaml" install

# 2. Start it
Start-Service ObsidianWatchAgent

# 3. Verify
Get-Service ObsidianWatchAgent
```

The service is registered with `StartAutomatic` — it starts on every boot.

**Service management:**
```powershell
Start-Service   ObsidianWatchAgent
Stop-Service    ObsidianWatchAgent
Restart-Service ObsidianWatchAgent

# View logs written by the service
Get-EventLog -LogName Application -Source ObsidianWatchAgent -Newest 50

# Remove the service
.\agent.exe uninstall
```

---

## Configuration

The agent is configured by a single YAML file. Pass it with `-config`:

```powershell
.\agent.exe -config "C:\path\to\agent.yaml"
```

If `-config` is omitted the agent looks for `agent.yaml` in the current directory.

### Full annotated agent.yaml

```yaml
agent:
  # Unique identifier for this agent.
  # Leave empty to use the machine hostname (recommended).
  id: ""
  version: "0.2.0"

collector:

  event_log:
    enabled: true
    # Windows Event Log channels to subscribe to.
    # Run: wevtutil el   to list all available channels on your system.
    channels:
      - Security
      - System
      - Application
      - Microsoft-Windows-PowerShell/Operational
    poll_interval: 5s

  sysmon:
    # Requires Sysmon to be installed separately.
    # https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    # If Sysmon is not installed this collector is skipped — no crash.
    enabled: true

  network:
    enabled: true
    # How often to snapshot the TCP connection table and emit deltas.
    poll_interval: 30s

  process:
    # Real-time process start/stop via ETW (Kernel-Process provider).
    # Automatically falls back to WMI/toolhelp polling if ETW fails.
    enabled: true

  registry:
    enabled: true
    # Registry key subtrees to watch for any change (create/delete/modify).
    # Supported prefixes: HKLM, HKCU, HKCR, HKU
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - HKLM\SYSTEM\CurrentControlSet\Services
      - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

  # DNS query/response telemetry via Microsoft-Windows-DNS-Client/Operational.
  # No Sysmon required. The agent auto-enables the channel if it is disabled.
  dns:
    enabled: true

  # File Integrity Monitoring.
  # Watches directories in real time for create, modify, delete, and rename.
  # Uses ReadDirectoryChangesW — no polling, true real-time notification.
  fim:
    enabled: true
    dirs:
      - path: "C:\\Windows\\System32"
        recursive: false
        # Glob patterns to exclude (matched against full path, case-insensitive)
        exclude:
          - "*.log"
          - "*.tmp"
          - "*.etl"
      - path: "C:\\Windows\\SysWOW64"
        recursive: false
        exclude:
          - "*.log"
          - "*.tmp"
          - "*.etl"
      # Add your own sensitive directories:
      # - path: "C:\\inetpub\\wwwroot"
      #   recursive: true
      #   exclude: []

  # Agent health heartbeat.
  # Emits a health event at each interval containing:
  #   uptime, agent version, active collectors, events collected/dropped/
  #   forwarded, queue depth, memory usage (MB), goroutine count.
  health:
    enabled: true
    interval: 60s

  # Per-source rate limiting and deduplication.
  # Prevents a noisy source from flooding the queue and backend.
  # Applied after collection, before the normalizer.
  rate_limit:
    enabled: true
    max_per_second: 500   # max events/sec per (event_type + source) key
    dedupe_window: 5s     # suppress duplicate event IDs within this window

  # Application log tailing.
  # Tails any log file and ships each new line as a SIEM event.
  # The byte offset is saved to disk and resumed after agent restart.
  # Log rotation is handled automatically (reopen from 0 if file shrinks).
  #
  # format:
  #   json     — extracts: time, level→severity, user, src_ip, dst_ip,
  #              port, process, pid. All other fields stored in Raw.
  #   text     — each line stored verbatim in Raw.
  #   combined — Apache / nginx combined access log. Extracts: src_ip,
  #              method, path, status code, bytes, user agent.
  #              HTTP 5xx → medium, 4xx → low.
  #
  # severity: 1=info  2=low  3=medium  4=high  5=critical
  #   JSON logs with a level/severity field override this automatically.
  app_logs: []

  # Examples:
  # app_logs:
  #   - name: "my-api"
  #     path: "C:\\logs\\my-api\\app.log"
  #     format: "json"
  #     event_type: "applog"
  #     severity: 2
  #
  #   - name: "nginx-access"
  #     path: "C:\\nginx\\logs\\access.log"
  #     format: "combined"
  #     event_type: "weblog"
  #     severity: 1
  #
  #   - name: "worker"
  #     path: "C:\\logs\\worker.log"
  #     format: "text"
  #     event_type: "applog"
  #     severity: 1

forwarder:
  # Full URL of the backend ingest API. Must include scheme and port.
  backend_url: "https://siem.yourcompany.com:8443"

  # Events to bundle into a single HTTP POST.
  batch_size: 200

  # Send a batch at this interval even if batch_size is not reached.
  flush_interval: 5s

  # mTLS (recommended for production).
  cert_file: "certs/agent.crt"
  key_file:  "certs/agent.key"
  ca_file:   "certs/ca.crt"

  # API key auth — simpler alternative to mTLS.
  # Remove cert_file / key_file above and uncomment:
  # api_key: "your-secret-key-here"

queue:
  # Directory for the offline event buffer.
  db_path: "C:\\ProgramData\\ObsidianWatch\\queue"
  # Max buffered events before oldest are evicted (ring buffer).
  max_rows: 100000

log:
  level: "info"    # debug | info | warn | error
  format: "json"   # json  | text
```

---

## TLS & Authentication

### Mode 1 — Mutual TLS (mTLS) — Recommended

Both the agent and backend present certificates. The agent verifies it is talking to the real backend; the backend verifies the agent is enrolled.

**Step 1 — Create a Certificate Authority (once, on the backend server):**
```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/C=US/O=ObsidianWatch/CN=ObsidianWatch-CA"
```

**Step 2 — Create the backend server certificate:**
```bash
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/O=ObsidianWatch/CN=siem.yourcompany.com"

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

**Step 3 — Create a certificate per agent host:**
```bash
HOSTNAME="workstation-01"
openssl genrsa -out ${HOSTNAME}.key 2048
openssl req -new -key ${HOSTNAME}.key -out ${HOSTNAME}.csr \
  -subj "/C=US/O=ObsidianWatch/CN=${HOSTNAME}"
openssl x509 -req -days 825 -in ${HOSTNAME}.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out ${HOSTNAME}.crt
```

**Step 4 — Deploy to the Windows host:**

Copy to `C:\Program Files\ObsidianWatch\Agent\certs\`:

| File | What it is |
|---|---|
| `agent.crt` | Agent client certificate (rename from `HOSTNAME.crt`) |
| `agent.key` | Agent private key (rename from `HOSTNAME.key`) |
| `ca.crt` | CA certificate — used to verify the backend |

**Step 5 — agent.yaml:**
```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  cert_file: "certs/agent.crt"
  key_file:  "certs/agent.key"
  ca_file:   "certs/ca.crt"
```

---

### Mode 2 — API Key

```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  ca_file: "certs/ca.crt"
  api_key: "your-secret-key-here"
```

The key is sent as `X-API-Key` on every request. Always use `https://` — never plain `http://`.

---

## Running the Agent

**Interactively (testing/debugging):**
```powershell
.\agent.exe -config agent.yaml
```
Logs print to stdout. Set `log.level: debug` for per-event output. Press `Ctrl+C` to stop.

**As a Windows Service:**
```powershell
.\agent.exe -config "C:\Program Files\ObsidianWatch\Agent\agent.yaml" install
Start-Service ObsidianWatchAgent
Get-Service   ObsidianWatchAgent
```

**Test backend connectivity:**
```powershell
Test-NetConnection -ComputerName siem.yourcompany.com -Port 8443
Invoke-WebRequest -Uri "https://siem.yourcompany.com:8443/health" -SkipCertificateCheck
```

---

## Offline Buffering

Events are written to JSONL segment files under `queue.db_path/segments/`. The forwarder reads them and POSTs to the backend. Failed POSTs are retried with exponential backoff and full jitter.

| Attempt | Max wait |
|---|---|
| 1 | ~500ms |
| 2 | ~1s |
| 3 | ~2s |
| 4 | ~4s |
| 5 | ~8s |
| 6 | ~16s |
| 7 | ~32s |
| 8 (final) | fail, re-queue |

**Inspect the queue:**
```powershell
Get-ChildItem "C:\ProgramData\ObsidianWatch\queue\segments\"

Get-Content "C:\ProgramData\ObsidianWatch\queue\segments\0000000001.jsonl" |
  ConvertFrom-Json | Select-Object time, event_type, host | Format-Table
```

---

## Collectors

### Collector overview

| Collector | Source | What it captures |
|---|---|---|
| **event_log** | wevtapi.dll | All configured Windows Event Log channels. Each event is fully XML-parsed: user, domain, PID, process name, command line, IP addresses, ports, registry key — extracted as individual schema fields, not raw XML. |
| **sysmon** | Sysmon Operational | 17 high-value Sysmon event IDs mapped to enriched events. Requires Sysmon installed. |
| **network** | iphlpapi.dll | TCP connection table snapshot every `poll_interval`. Emits connect/disconnect events with PID, src/dst IP and port. |
| **process** | ETW Kernel-Process | Real-time process start and stop. Uses `StartTrace → EnableTraceEx2 → OpenTrace → ProcessTrace`. Falls back to `CreateToolhelp32Snapshot` polling if ETW is unavailable (e.g. insufficient privileges). |
| **registry** | RegNotifyChangeKeyValue | Fires on any change to watched key subtrees — create, delete, or value modification. |
| **dns** | DNS-Client/Operational | DNS query name, type, results, and status. No Sysmon required. Agent auto-enables the channel if it is disabled. |
| **fim** | ReadDirectoryChangesW | File and directory create, modify, delete, rename in watched paths. Sensitivity-based severity — changes in System32 are rated High. |
| **applog** | Any log file | Tails files from the last saved offset. JSON logs: extracts `time`, `level`, `user`, `src_ip`, `dst_ip`, `port`, `pid`, `process`. Combined logs: parses method, path, status, bytes, user agent. Text logs: stores lines verbatim. Handles rotation. |
| **health** | Agent itself | Heartbeat every 60s: uptime, agent version, active collectors, events collected / dropped / forwarded, queue depth, memory (MB), goroutines. |
| **rate_limit** | All sources | Wraps the collector pipeline. Drops events that exceed `max_per_second` per source, and suppresses duplicate event IDs within `dedupe_window`. |

---

### Windows Security Event IDs — detailed handling

| Event ID | Description | event_type | Severity |
|---|---|---|---|
| 4624 | Successful logon | logon | Info (Low if network, Medium if RDP) |
| 4625 | Failed logon | logon | Medium (High if remote network) |
| 4634 / 4647 | Logoff | logon | Info |
| 4648 | Explicit credentials used (runas / pass-the-hash indicator) | logon | Medium |
| 4672 | Special privileges assigned (admin logon) | logon | Medium |
| 4688 | Process creation | process | Low |
| 4689 | Process termination | process | Info |
| 4698 / 4702 | Scheduled task created / updated | process | High |
| 4720 | User account created | logon | High |
| 4728 / 4732 / 4756 | Member added to privileged group | logon | High |
| 4657 | Registry value modified | registry | Medium |
| 4660 | Object deleted | file | Medium |
| 4663 | Object access | file | Low |
| 4776 | NTLM credential validation | logon | Low |
| 5156 | Windows Filtering Platform — connection permitted | network | Low |
| 5157 | Windows Filtering Platform — connection blocked | network | Medium |
| 7045 | New service installed | process | High |

---

### Sysmon Event ID coverage

| ID | Name | Severity |
|---|---|---|
| 1 | ProcessCreate | Low |
| 3 | NetworkConnect | Low |
| 5 | ProcessTerminate | Info |
| 6 | DriverLoad | High |
| 7 | ImageLoad | Low |
| 8 | CreateRemoteThread | High |
| 9 | RawAccessRead | High |
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

---

### Severity scale

| Value | Label | Examples |
|---|---|---|
| 1 | Info | Logoff, process exit, DNS cache hit, health heartbeat |
| 2 | Low | New TCP connection, file create, DNS query, process start |
| 3 | Medium | Failed logon, registry change, firewall block, RDP logon |
| 4 | High | Remote thread injection, driver load, new service, account created, group membership change, scheduled task |
| 5 | Critical | Windows Critical level events |

---

### Event schema fields

Every event carries these fields regardless of source:

| Field | Type | Description |
|---|---|---|
| `id` | string | Deterministic SHA-256 derived dedup key |
| `time` | RFC3339 | Event timestamp (UTC) |
| `agent_id` | string | Agent identifier (hostname or configured ID) |
| `host` | string | Hostname of the collecting machine |
| `os` | string | `windows` |
| `event_type` | string | `logon` `process` `network` `registry` `file` `sysmon` `dns` `applog` `health` `raw` |
| `severity` | int | 1–5 |
| `source` | string | Channel or provider name |
| `raw` | JSON | Full original payload for forensic fidelity |
| `event_id` | uint32 | Windows Event ID (where applicable) |
| `channel` | string | Event Log channel name |
| `user_name` | string | Subject or target user |
| `domain` | string | Subject or target domain |
| `logon_id` | string | Logon session ID |
| `pid` | int | Process ID |
| `ppid` | int | Parent process ID |
| `process_name` | string | Process image name |
| `command_line` | string | Full command line (truncated at 4096 chars) |
| `image_path` | string | Full path to process image |
| `src_ip` | string | Source IP address |
| `src_port` | int | Source port |
| `dst_ip` | string | Destination IP address (or queried DNS hostname) |
| `dst_port` | int | Destination port |
| `proto` | string | `tcp` `udp` `icmp` |
| `reg_key` | string | Registry key path |
| `reg_value` | string | Registry value name |
| `reg_data` | string | New registry value data |
| `file_path` | string | File or object path |
| `file_hash` | string | File hash (where available) |

---

## Project Structure

```
agent/
├── cmd/
│   └── agent/
│       └── main.go                  # Entry point, Windows service wiring, collector startup
├── internal/
│   ├── collector/
│   │   ├── eventlog.go              # Windows Event Log — full XML parse, all fields extracted
│   │   ├── sysmon.go                # Sysmon Operational channel — 17 event IDs mapped
│   │   ├── network.go               # TCP table snapshot via iphlpapi.dll — connect/disconnect diffs
│   │   ├── process.go               # ETW Kernel-Process — real-time start/stop, WMI fallback
│   │   ├── registry.go              # Registry watcher via RegNotifyChangeKeyValue
│   │   ├── dns.go                   # DNS-Client/Operational — query/response telemetry
│   │   ├── fim.go                   # File Integrity Monitoring via ReadDirectoryChangesW
│   │   ├── applog.go                # Application log tailer — json / text / combined formats
│   │   ├── health.go                # Agent health heartbeat reporter
│   │   └── ratelimit.go             # Per-source rate limiter and deduplicator
│   ├── parser/
│   │   ├── normalizer.go            # Field hygiene, EventID → type/severity classification
│   │   └── enricher.go              # Agent ID, hostname, deterministic dedup ID
│   ├── forwarder/
│   │   ├── http.go                  # HTTP/2 + mTLS batched forwarder
│   │   ├── queue.go                 # Durable JSONL segment queue (stdlib only, no SQLite)
│   │   └── retry.go                 # Exponential backoff with full jitter
│   └── config/
│       └── config.go                # YAML config loader, struct definitions, defaults, validation
├── pkg/
│   └── schema/
│       └── event.go                 # Shared Event and Batch types (single source of truth)
├── configs/
│   └── agent.yaml                   # Default configuration template
└── go.mod
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE) for details.
