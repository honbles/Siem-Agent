# Configuration Reference

This document covers every field in `agent.yaml` with accepted values, defaults, and examples.

---

## File Location

By default the agent looks for `agent.yaml` in the current working directory. Override with:

```powershell
agent.exe -config "C:\Program Files\OpenSIEM\Agent\agent.yaml"
```

All file paths inside `agent.yaml` (cert files, queue path) are **relative to the location of `agent.yaml`** unless you use absolute paths.

---

## Top-Level Sections

| Section | Purpose |
|---|---|
| `agent` | Identity and version |
| `collector` | Which event sources to enable and how to poll them |
| `forwarder` | Backend URL, batch settings, TLS/auth credentials |
| `queue` | Offline buffer location and size limit |
| `log` | Log level and output format |

---

## `agent`

```yaml
agent:
  id: ""
  version: "0.1.0"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `id` | string | `""` | Unique identifier for this agent. If empty, the machine hostname is used. Set explicitly if you have multiple agents on the same host or want a stable ID regardless of hostname changes. |
| `version` | string | `"0.1.0"` | Reported in every batch sent to the backend. Used by the backend to track agent versions across your fleet. Do not change unless you are building a custom version. |

---

## `collector`

Controls which telemetry sources are active and how they are polled.

### `collector.event_log`

```yaml
collector:
  event_log:
    enabled: true
    channels:
      - Security
      - System
      - Application
      - Microsoft-Windows-PowerShell/Operational
    poll_interval: 5s
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable or disable the Windows Event Log collector. |
| `channels` | list of strings | `[Security, System, Application]` | Event Log channel names to subscribe to. Run `wevtutil el` in PowerShell to see all available channels on your system. |
| `poll_interval` | duration | `5s` | How often to drain pending events from the subscription handles. Shorter intervals reduce latency. Valid units: `ms`, `s`, `m`. |

**Commonly useful channels:**

| Channel | What it contains |
|---|---|
| `Security` | Logon/logoff, privilege use, account changes, process creation (if auditing enabled) |
| `System` | Service start/stop, driver load, system errors |
| `Application` | Application crashes, Windows Defender events |
| `Microsoft-Windows-PowerShell/Operational` | PowerShell script execution |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI activity — useful for detecting WMI-based attacks |
| `Microsoft-Windows-TaskScheduler/Operational` | Scheduled task creation and execution |
| `Microsoft-Windows-Windows Defender/Operational` | Defender detections and scan results |

---

### `collector.sysmon`

```yaml
collector:
  sysmon:
    enabled: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable Sysmon event collection. **Requires Sysmon to be installed separately.** If Sysmon is not installed and this is `true`, the collector will log an error and skip. |

**Installing Sysmon:**

Download from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and install with a configuration file:

```powershell
# Install with a community config (SwiftOnSecurity is a good starting point)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmonconfig.xml
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify it's running
Get-Service Sysmon64
```

---

### `collector.network`

```yaml
collector:
  network:
    enabled: true
    poll_interval: 30s
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable TCP connection monitoring. |
| `poll_interval` | duration | `30s` | How often to snapshot the TCP connection table and emit connect/disconnect events. Lower values catch short-lived connections but increase CPU load. |

The network collector **diffs** each snapshot against the previous one — it only emits events for connections that newly appeared (connect) or disappeared (disconnect). It does not emit an event for every existing connection on every poll.

---

### `collector.process`

```yaml
collector:
  process:
    enabled: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable ETW-based process creation/termination collection. |

This collector uses Event Tracing for Windows (ETW) with the `Microsoft-Windows-Kernel-Process` provider. It runs in real-time and does not require polling.

> **Note:** The ETW integration in v0.1.0 establishes the session framework. Full `ImageFileName` and `CommandLine` extraction from the TDH schema is a planned contribution. For full process telemetry right now, enable Sysmon (which provides Event ID 1 — ProcessCreate with full command line).

---

### `collector.registry`

```yaml
collector:
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
      - HKLM\SYSTEM\CurrentControlSet\Services
      - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Enable registry change monitoring. |
| `keys` | list of strings | See above | Registry keys to watch. Any change to the key or any of its subkeys/values triggers an event. |

**Supported hive prefixes:**

| Prefix | Full name |
|---|---|
| `HKLM` or `HKEY_LOCAL_MACHINE` | Local machine |
| `HKCU` or `HKEY_CURRENT_USER` | Current user |
| `HKCR` or `HKEY_CLASSES_ROOT` | Classes root |
| `HKU` or `HKEY_USERS` | All users |

**High-value keys to monitor:**

```yaml
keys:
  # Persistence mechanisms
  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
  - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

  # Services (malware often installs as a service)
  - HKLM\SYSTEM\CurrentControlSet\Services

  # AppInit DLLs (classic injection vector)
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows

  # Winlogon hooks
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

  # LSA authentication packages
  - HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```

---

## `forwarder`

Controls how events are delivered to the backend.

```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  batch_size: 200
  flush_interval: 5s
  cert_file: "certs/agent.crt"
  key_file:  "certs/agent.key"
  ca_file:   "certs/ca.crt"
  # api_key: "your-key-here"
```

| Field | Type | Default | Description |
|---|---|---|---|
| `backend_url` | string | **required** | Full HTTPS URL of the backend ingest endpoint. Must include scheme (`https://`) and port. |
| `batch_size` | int | `200` | Maximum number of events per HTTP POST. Larger batches are more efficient but increase latency. |
| `flush_interval` | duration | `5s` | Send a batch at this interval even if `batch_size` has not been reached. This caps the maximum delivery delay. |
| `cert_file` | string | `""` | Path to the agent's TLS client certificate (PEM format). Required for mTLS. |
| `key_file` | string | `""` | Path to the agent's TLS private key (PEM format). Required for mTLS. |
| `ca_file` | string | `""` | Path to the CA certificate used to verify the backend's server certificate (PEM format). Required when using a self-signed or private CA. |
| `api_key` | string | `""` | API key sent as `X-API-Key` header. Used when mTLS is not configured. |

**Authentication priority:** If `cert_file` and `key_file` are set, mTLS is used. If only `api_key` is set, header-based auth is used. If neither is set, requests are sent without authentication (only appropriate for local/dev setups).

---

## `queue`

The offline buffer stores events locally when the backend is unreachable.

```yaml
queue:
  db_path: "C:\\ProgramData\\OpenSIEM\\queue"
  max_rows: 100000
```

| Field | Type | Default | Description |
|---|---|---|---|
| `db_path` | string | `"agent_queue.db"` | Directory path for the queue. The agent creates a `segments/` subfolder here. Use an absolute path in production. On Windows, escape backslashes (`\\`) or use forward slashes. |
| `max_rows` | int | `100000` | Maximum number of events to keep in the buffer. When this limit is exceeded, the oldest events are deleted to make room. At 200 events/batch and 5s flush, 100k events is roughly 40 minutes of buffering at moderate load. |

**Queue on disk:**

```
C:\ProgramData\OpenSIEM\queue\
  segments\
    0000000001.jsonl    <- oldest (consumed first)
    0000000002.jsonl
    0000000003.jsonl    <- currently being written
```

Each `.jsonl` file holds up to 500 events, one JSON object per line. You can open these files in any text editor to inspect buffered events.

---

## `log`

```yaml
log:
  level: "info"
  format: "json"
```

| Field | Type | Default | Options | Description |
|---|---|---|---|---|
| `level` | string | `"info"` | `debug`, `info`, `warn`, `error` | Minimum log level to emit. Use `debug` when troubleshooting — it logs every event dropped by the normalizer. |
| `format` | string | `"json"` | `json`, `text` | Log output format. Use `json` for production (structured, parseable). Use `text` for local debugging (human-readable). |

**Example JSON log line:**
```json
{"time":"2024-01-15T13:45:01.234Z","level":"INFO","msg":"forwarder: sent batch","count":47}
```

**Example text log line:**
```
2024/01/15 13:45:01 INFO forwarder: sent batch count=47
```

---

## Environment-specific examples

### Corporate workstation (mTLS, Sysmon enabled)

```yaml
agent:
  id: ""
  version: "0.1.0"

collector:
  event_log:
    enabled: true
    channels:
      - Security
      - System
      - Microsoft-Windows-PowerShell/Operational
      - Microsoft-Windows-TaskScheduler/Operational
    poll_interval: 5s
  sysmon:
    enabled: true
  network:
    enabled: true
    poll_interval: 15s
  process:
    enabled: true
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
      - HKLM\SYSTEM\CurrentControlSet\Services
      - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon

forwarder:
  backend_url: "https://siem.corp.internal:8443"
  batch_size: 500
  flush_interval: 10s
  cert_file: "C:\\Program Files\\OpenSIEM\\Agent\\certs\\agent.crt"
  key_file:  "C:\\Program Files\\OpenSIEM\\Agent\\certs\\agent.key"
  ca_file:   "C:\\Program Files\\OpenSIEM\\Agent\\certs\\ca.crt"

queue:
  db_path: "C:\\ProgramData\\OpenSIEM\\queue"
  max_rows: 200000

log:
  level: "info"
  format: "json"
```

### Dev / lab setup (API key, no Sysmon, local backend)

```yaml
agent:
  id: "dev-test-01"
  version: "0.1.0"

collector:
  event_log:
    enabled: true
    channels: [Security, System]
    poll_interval: 10s
  sysmon:
    enabled: false
  network:
    enabled: true
    poll_interval: 60s
  process:
    enabled: false
  registry:
    enabled: false
    keys: []

forwarder:
  backend_url: "https://localhost:8443"
  batch_size: 50
  flush_interval: 3s
  api_key: "dev-secret-key"

queue:
  db_path: "queue"
  max_rows: 10000

log:
  level: "debug"
  format: "text"
```
