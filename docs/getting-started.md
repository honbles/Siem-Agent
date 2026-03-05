# Getting Started

This guide gets you from zero to a running agent in under 15 minutes using API key authentication (the simplest path). For production deployments, follow up with the [TLS Setup guide](tls-setup.md).

---

## What you need

- A Windows 10 / Server 2016+ machine to monitor (64-bit)
- Administrator access on that machine
- A backend server running the OpenSIEM ingest API (or a test endpoint — see below)
- Go 1.22+ if you are building from source

---

## Step 1 — Build the agent

**On Windows:**
```powershell
git clone https://github.com/YOUR_ORG/opensiem.git
cd opensiem\agent
go mod tidy
go build -o agent.exe .\cmd\agent
```

**Cross-compile from Linux / macOS:**
```bash
git clone https://github.com/YOUR_ORG/opensiem.git
cd opensiem/agent
go mod tidy
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
```

You now have a single `agent.exe` file. Copy it to the Windows machine.

---

## Step 2 — Create a config file

Copy `configs/agent.yaml` to the same folder as `agent.exe`, then edit it.

At minimum you need to set `forwarder.backend_url`. Everything else has working defaults.

```yaml
# agent.yaml — minimal working config

agent:
  id: ""          # leave blank to use hostname
  version: "0.1.0"

collector:
  event_log:
    enabled: true
    channels: [Security, System, Application]
    poll_interval: 5s
  sysmon:
    enabled: false   # set true if Sysmon is installed
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
  backend_url: "https://your-backend-server:8443"   # ← CHANGE THIS
  batch_size: 200
  flush_interval: 5s
  api_key: "change-this-to-a-strong-random-key"     # ← CHANGE THIS

queue:
  db_path: "C:\\ProgramData\\OpenSIEM\\queue"
  max_rows: 100000

log:
  level: "info"
  format: "json"
```

---

## Step 3 — Test the agent interactively

Before installing as a service, run the agent in your PowerShell terminal to confirm it starts cleanly and can reach the backend. **Run as Administrator.**

```powershell
# Open an elevated PowerShell prompt, then:
cd "C:\path\to\agent"
.\agent.exe -config agent.yaml
```

You should see output like:
```json
{"time":"...","level":"INFO","msg":"collector: starting","name":"eventlog"}
{"time":"...","level":"INFO","msg":"eventlog: subscribed","channel":"Security"}
{"time":"...","level":"INFO","msg":"eventlog: subscribed","channel":"System"}
{"time":"...","level":"INFO","msg":"collector: starting","name":"network"}
{"time":"...","level":"INFO","msg":"forwarder: started","url":"https://your-backend:8443"}
```

If you see `forwarder: send failed after retries` it means the agent can't reach the backend — check your `backend_url`, firewall rules, and that the backend is running.

Press `Ctrl+C` to stop.

---

## Step 4 — Install as a Windows Service

Once the agent runs cleanly in interactive mode, install it as a service so it starts automatically:

```powershell
# From an elevated PowerShell prompt
.\agent.exe -config "C:\Program Files\OpenSIEM\Agent\agent.yaml" install
Start-Service OpenSIEMAgent
Get-Service OpenSIEMAgent
```

Or use the PowerShell installer script for a more complete setup:

```powershell
.\build\windows\install.ps1 -Action install -BackendURL "https://your-backend:8443"
```

---

## Step 5 — Verify events are flowing

Check the service is running and events are being sent:

```powershell
# Check service status
Get-Service OpenSIEMAgent

# Tail the Windows Event Log for agent messages
Get-EventLog -LogName Application -Source OpenSIEMAgent -Newest 20

# Check the queue (should drain to near-zero if backend is reachable)
Get-ChildItem "C:\ProgramData\OpenSIEM\queue\segments" | Measure-Object | Select-Object Count
```

On the backend side you should see `POST /api/v1/events` requests arriving every 5 seconds (the default `flush_interval`).

---

## Test with a local mock backend

If you don't have the backend running yet, you can use `netcat` or a simple HTTPS echo server to verify the agent is sending correctly.

**Using Python (Linux/Mac) as a quick HTTPS sink:**

```python
# save as fake_backend.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl, json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = json.loads(self.rfile.read(length))
        print(f"Received {len(body['events'])} events from agent {body['agent_id']}")
        for ev in body['events'][:3]:
            print(f"  {ev['time']} [{ev['event_type']}] {ev.get('process_name','')}")
        self.send_response(200)
        self.end_headers()
    def log_message(self, *args): pass

server = HTTPServer(('0.0.0.0', 8443), Handler)
# For HTTPS, wrap with SSL (needs server.crt/server.key)
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.load_cert_chain('server.crt', 'server.key')
# server.socket = context.wrap_socket(server.socket, server_side=True)
print("Listening on :8443")
server.serve_forever()
```

```bash
python3 fake_backend.py
```

Then set `backend_url: "http://your-linux-ip:8443"` in `agent.yaml` for this test only. Switch to `https://` for real use.

---

## Common first-run issues

### "Access is denied" when subscribing to Security channel

The agent must run as Administrator (or SYSTEM when running as a service). If running interactively, make sure you opened PowerShell as Administrator.

### "config: validate: forwarder.backend_url is required"

You didn't set `backend_url` in `agent.yaml`. It is the only required field.

### "eventlog: no channels could be subscribed"

All the channels in your config failed to open. This usually means:
- The channel name has a typo — verify with `wevtutil el | findstr -i security`
- The agent is not running with sufficient privileges

### Service installs but immediately stops

Check the Windows Event Log for details:
```powershell
Get-EventLog -LogName System -EntryType Error -Newest 10 | 
  Where-Object Source -like "*OpenSIEM*"
```

Common cause: `agent.yaml` path passed to the service is wrong. The path must be absolute when running as a service.

### Firewall blocking outbound connection

```powershell
# Add a Windows Firewall rule to allow outbound to the backend
New-NetFirewallRule -DisplayName "OpenSIEM Agent Outbound" `
  -Direction Outbound `
  -Action Allow `
  -Protocol TCP `
  -RemotePort 8443
```

---

## Next steps

- [Configuration Reference](configuration.md) — all config fields explained
- [TLS Setup](tls-setup.md) — set up mTLS for production
- Backend setup — coming soon
