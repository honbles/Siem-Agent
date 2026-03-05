# Event Schema Reference

Every event collected by the agent is normalized into a common `Event` struct before being forwarded to the backend. This document describes every field.

---

## Batch envelope

Events are delivered in batches. Each HTTP POST to `/api/v1/events` contains one batch:

```json
{
  "agent_id": "workstation-01",
  "agent_version": "0.1.0",
  "sent_at": "2024-01-15T13:45:01.234Z",
  "events": [ ...Event objects... ]
}
```

| Field | Type | Description |
|---|---|---|
| `agent_id` | string | The agent's identifier (hostname or configured `agent.id`) |
| `agent_version` | string | The agent binary version |
| `sent_at` | RFC3339 timestamp | When this batch was sent |
| `events` | array | Array of Event objects (see below) |

---

## Event object

### Core fields (always present)

| Field | Type | Description |
|---|---|---|
| `id` | string | Deterministic 32-char hex ID for deduplication. Derived from time + agent + source + record_id. |
| `time` | RFC3339 timestamp | When the event occurred (from the event source, not delivery time) |
| `agent_id` | string | Agent that collected the event |
| `host` | string | Hostname of the Windows machine |
| `os` | string | Always `"windows"` for this agent |
| `event_type` | string | Classification — see Event Types below |
| `severity` | integer | 1–5 severity scale — see Severity Scale below |
| `source` | string | Which subsystem produced the event (e.g. `"Security"`, `"Sysmon"`, `"iphlpapi"`) |
| `raw` | JSON object | The original, unmodified event payload for forensic fidelity |

### Process fields

Present on `event_type: process` and `event_type: sysmon` events.

| Field | Type | Description |
|---|---|---|
| `pid` | integer | Process ID |
| `ppid` | integer | Parent process ID |
| `process_name` | string | Image name / executable path |
| `command_line` | string | Full command line (truncated to 4096 chars if longer) |
| `image_path` | string | Full path to the executable on disk |

### Identity fields

Present on logon events and process events where user context is available.

| Field | Type | Description |
|---|---|---|
| `user_name` | string | Account name that performed the action |
| `domain` | string | Domain or machine name of the account |
| `logon_id` | string | Windows logon session ID (hex) |

### Network fields

Present on `event_type: network` events.

| Field | Type | Description |
|---|---|---|
| `src_ip` | string | Source IP address |
| `src_port` | integer | Source port |
| `dst_ip` | string | Destination IP address |
| `dst_port` | integer | Destination port |
| `proto` | string | Protocol — `"tcp"` or `"udp"` |

### Registry fields

Present on `event_type: registry` events.

| Field | Type | Description |
|---|---|---|
| `reg_key` | string | Full registry key path (e.g. `HKLM\SOFTWARE\...`) |
| `reg_value` | string | Name of the changed value |
| `reg_data` | string | New data written to the value |

### File fields

Present on `event_type: file` and some Sysmon events.

| Field | Type | Description |
|---|---|---|
| `file_path` | string | Full path to the affected file |
| `file_hash` | string | Hash(es) of the file — format depends on Sysmon config (e.g. `SHA256=abc...`) |

### Windows Event Log fields

Present on events sourced from the Windows Event Log.

| Field | Type | Description |
|---|---|---|
| `event_id` | integer | Windows Event ID (e.g. 4624, 4688) |
| `channel` | string | Event Log channel name (e.g. `"Security"`) |
| `record_id` | integer | Sequential record number within the channel |

---

## Event Types

The `event_type` field classifies what kind of security event this is.

| Value | Description | Primary source |
|---|---|---|
| `process` | Process creation or termination | Security (4688/4689), ETW, Sysmon (1/5) |
| `network` | Network connection or disconnection | `iphlpapi` snapshot, Sysmon (3), Security (5156) |
| `logon` | User logon, logoff, or credential use | Security (4624, 4625, 4634, 4648, 4672) |
| `registry` | Registry key or value change | `RegNotifyChangeKeyValue`, Sysmon (12-14) |
| `file` | File creation, deletion, or access | Security (4663), Sysmon (11, 15, 23) |
| `sysmon` | Sysmon event with no more specific classification | Sysmon (unrecognized IDs) |
| `raw` | Event that could not be classified | Any source |

---

## Severity Scale

| Value | Label | Meaning | Example events |
|---|---|---|---|
| `1` | Info | Routine activity, no action needed | Process exit, user logoff |
| `2` | Low | Normal activity worth recording | New TCP connection, file created |
| `3` | Medium | Warrants review | Failed logon (4625), registry change, WMI activity |
| `4` | High | Investigate promptly | Remote thread injection (Sysmon 8), driver load (Sysmon 6), account created (4720) |
| `5` | Critical | Immediate attention required | Windows Critical-level events |

---

## Windows Security EventID → Severity mapping

The normalizer automatically raises severity for high-signal EventIDs:

| EventID | Description | Assigned Severity |
|---|---|---|
| 4624 | Successful logon | Info (1) |
| 4625 | Failed logon | **Medium (3)** |
| 4634 | Account logoff | Info (1) |
| 4648 | Logon with explicit credentials | **Medium (3)** |
| 4672 | Special privileges assigned (admin logon) | **Medium (3)** |
| 4688 | Process creation | Low (2) |
| 4689 | Process termination | Info (1) |
| 4698 | Scheduled task created | **High (4)** |
| 4702 | Scheduled task modified | **High (4)** |
| 4720 | User account created | **High (4)** |
| 4728 | Member added to security-enabled global group | **High (4)** |
| 4732 | Member added to security-enabled local group | **High (4)** |
| 4756 | Member added to security-enabled universal group | **High (4)** |
| 4776 | Credential validation | **Medium (3)** |
| 5156 | Network connection allowed | Low (2) |
| 5157 | Network connection blocked | **Medium (3)** |

---

## Example events

### Logon event (EventID 4624)

```json
{
  "id": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "time": "2024-01-15T13:45:00.123Z",
  "agent_id": "workstation-01",
  "host": "WORKSTATION-01",
  "os": "windows",
  "event_type": "logon",
  "severity": 1,
  "source": "Security",
  "event_id": 4624,
  "channel": "Security",
  "record_id": 884201,
  "user_name": "jsmith",
  "domain": "CORP",
  "logon_id": "0x3e7",
  "raw": { "EventID": 4624, "Channel": "Security", "RawXML": "..." }
}
```

### Process creation (Sysmon EventID 1)

```json
{
  "id": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7",
  "time": "2024-01-15T13:45:01.456Z",
  "agent_id": "workstation-01",
  "host": "WORKSTATION-01",
  "os": "windows",
  "event_type": "process",
  "severity": 2,
  "source": "Sysmon",
  "event_id": 1,
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "pid": 4821,
  "ppid": 1234,
  "process_name": "C:\\Windows\\System32\\cmd.exe",
  "command_line": "cmd.exe /c whoami",
  "user_name": "jsmith",
  "file_hash": "SHA256=a1b2c3...",
  "raw": { "EventID": 1, "EventName": "ProcessCreate", "Image": "C:\\Windows\\System32\\cmd.exe", ... }
}
```

### Network connection

```json
{
  "id": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
  "time": "2024-01-15T13:45:02.789Z",
  "agent_id": "workstation-01",
  "host": "WORKSTATION-01",
  "os": "windows",
  "event_type": "network",
  "severity": 2,
  "source": "iphlpapi",
  "pid": 4821,
  "src_ip": "192.168.1.50",
  "src_port": 52341,
  "dst_ip": "93.184.216.34",
  "dst_port": 443,
  "proto": "tcp",
  "raw": { "state": "connect", "pid": 4821, "src_ip": "192.168.1.50", ... }
}
```

### Registry change

```json
{
  "id": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9",
  "time": "2024-01-15T13:45:10.000Z",
  "agent_id": "workstation-01",
  "host": "WORKSTATION-01",
  "os": "windows",
  "event_type": "registry",
  "severity": 3,
  "source": "RegNotify",
  "reg_key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "raw": { "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "action": "changed", "timestamp": "..." }
}
```
