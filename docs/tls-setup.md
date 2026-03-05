# TLS & Certificate Setup

This guide walks through setting up TLS certificates for agent-to-backend communication. It covers both production (mTLS) and simplified (API key) setups.

---

## Why TLS Matters

All communication between agents and the backend carries sensitive security telemetry — process names, network connections, user logon activity. Without TLS:

- Events travel in plaintext over the network
- Any machine on the path can read or inject events
- You cannot verify you are talking to your actual backend

**Always use HTTPS.** Never set `backend_url` to `http://`.

---

## Option A — Mutual TLS (mTLS)

With mTLS, **both sides** present a certificate:

- The agent presents its client certificate → the backend knows the agent is enrolled
- The backend presents its server certificate → the agent knows it's talking to the real backend

This is the recommended production setup. It provides strong identity for every agent and makes it impossible for a rogue host to submit events.

### Overview of what you will create

```
CA (Certificate Authority)          ← your root of trust, created once
├── server.crt / server.key         ← installed on the backend
├── agent-host1.crt / .key          ← deployed to workstation-1
├── agent-host2.crt / .key          ← deployed to workstation-2
└── ...
```

The CA certificate (`ca.crt`) is the only file that needs to be on every machine.

---

### Step 1 — Create the Certificate Authority

Run these commands **once**, on a secure machine (your backend server or a dedicated PKI host). Store the CA key safely — anyone with `ca.key` can issue trusted agent certificates.

```bash
# Create a directory to keep your CA files organised
mkdir -p ~/opensiem-pki && cd ~/opensiem-pki

# Generate the CA private key (4096-bit RSA)
openssl genrsa -out ca.key 4096

# Create the self-signed CA certificate (valid 10 years)
openssl req -new -x509 -days 3650 \
  -key ca.key \
  -out ca.crt \
  -subj "/C=US/ST=YourState/O=YourOrg/CN=OpenSIEM-CA"
```

Verify the CA certificate:
```bash
openssl x509 -in ca.crt -noout -text | grep -E "Subject:|Validity|Not After"
```

---

### Step 2 — Create the Backend Server Certificate

Run these commands on or for your backend server. Replace `siem.yourcompany.com` and `192.168.1.100` with your actual hostname and IP.

```bash
cd ~/opensiem-pki

# Generate backend private key
openssl genrsa -out server.key 2048

# Generate a Certificate Signing Request (CSR)
openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/C=US/O=YourOrg/CN=siem.yourcompany.com"

# Create a SANs extension file
# Add every hostname and IP address agents will use to connect
cat > server-ext.cnf << 'EOF'
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[v3_req]
subjectAltName = @alt_names
[alt_names]
DNS.1 = siem.yourcompany.com
DNS.2 = siem.corp.internal
IP.1  = 192.168.1.100
EOF

# Sign the server certificate with your CA
openssl x509 -req -days 825 \
  -in server.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out server.crt \
  -extfile server-ext.cnf \
  -extensions v3_req

# Verify the certificate
openssl x509 -in server.crt -noout -text | grep -A3 "Subject Alternative Name"
```

**Deploy to the backend:**
- `server.crt` → backend TLS certificate
- `server.key` → backend TLS private key
- `ca.crt` → backend uses this to verify agent client certificates

---

### Step 3 — Create Agent Certificates

Run this for each Windows host you want to enroll. Replace `workstation-01` with the actual hostname.

```bash
cd ~/opensiem-pki
AGENT="workstation-01"

# Generate agent private key
openssl genrsa -out ${AGENT}.key 2048

# Generate CSR
openssl req -new \
  -key ${AGENT}.key \
  -out ${AGENT}.csr \
  -subj "/C=US/O=YourOrg/CN=${AGENT}"

# Sign with your CA
openssl x509 -req -days 825 \
  -in ${AGENT}.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out ${AGENT}.crt

echo "Done. Files: ${AGENT}.crt  ${AGENT}.key  ca.crt"
```

**Repeat for every agent host.** Each agent gets its own unique key pair — this way you can revoke a single compromised host without affecting others.

---

### Step 4 — Deploy Certificates to the Windows Host

Copy three files to the Windows host. The recommended location is inside the agent install directory:

```
C:\Program Files\OpenSIEM\Agent\certs\
    agent.crt      ← rename from workstation-01.crt
    agent.key      ← rename from workstation-01.key
    ca.crt         ← same CA cert for all agents
```

**Option A — Copy over the network:**
```powershell
# On the Windows host (PowerShell)
New-Item -ItemType Directory -Path "C:\Program Files\OpenSIEM\Agent\certs" -Force

# Copy from wherever you stored them (adjust path)
Copy-Item "\\fileserver\opensiem-certs\workstation-01.crt" `
  "C:\Program Files\OpenSIEM\Agent\certs\agent.crt"
Copy-Item "\\fileserver\opensiem-certs\workstation-01.key" `
  "C:\Program Files\OpenSIEM\Agent\certs\agent.key"
Copy-Item "\\fileserver\opensiem-certs\ca.crt" `
  "C:\Program Files\OpenSIEM\Agent\certs\ca.crt"
```

**Option B — SCP from Linux/Mac:**
```bash
scp workstation-01.crt Administrator@192.168.1.50:"C:/Program Files/OpenSIEM/Agent/certs/agent.crt"
scp workstation-01.key Administrator@192.168.1.50:"C:/Program Files/OpenSIEM/Agent/certs/agent.key"
scp ca.crt              Administrator@192.168.1.50:"C:/Program Files/OpenSIEM/Agent/certs/ca.crt"
```

**Secure the private key:**
```powershell
# Restrict agent.key so only SYSTEM and Administrators can read it
$acl = Get-Acl "C:\Program Files\OpenSIEM\Agent\certs\agent.key"
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
  "SYSTEM", "Read", "Allow")
$acl.SetAccessRule($rule)
Set-Acl "C:\Program Files\OpenSIEM\Agent\certs\agent.key" $acl
```

---

### Step 5 — Configure `agent.yaml`

```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  cert_file: "certs/agent.crt"
  key_file:  "certs/agent.key"
  ca_file:   "certs/ca.crt"
```

If `agent.yaml` is at `C:\Program Files\OpenSIEM\Agent\agent.yaml`, the paths above resolve to the `certs\` folder in the same directory. You can also use absolute paths:

```yaml
  cert_file: "C:\\Program Files\\OpenSIEM\\Agent\\certs\\agent.crt"
  key_file:  "C:\\Program Files\\OpenSIEM\\Agent\\certs\\agent.key"
  ca_file:   "C:\\Program Files\\OpenSIEM\\Agent\\certs\\ca.crt"
```

---

### Step 6 — Verify the Connection

Test from the Windows host before starting the service:

```powershell
# Test that the backend is reachable
Test-NetConnection -ComputerName siem.yourcompany.com -Port 8443

# Test TLS handshake with the agent cert
# (requires openssl on the Windows host, or use WSL)
openssl s_client -connect siem.yourcompany.com:8443 \
  -cert "C:\Program Files\OpenSIEM\Agent\certs\agent.crt" \
  -key  "C:\Program Files\OpenSIEM\Agent\certs\agent.key" \
  -CAfile "C:\Program Files\OpenSIEM\Agent\certs\ca.crt"
```

A successful mTLS handshake shows:
```
SSL handshake has read ... bytes
Verify return code: 0 (ok)
```

---

## Option B — API Key Authentication

This is simpler to set up but provides no per-agent identity. All agents share the same key, and the backend cannot distinguish which specific host sent a batch (beyond what's in the event payload).

### Setup

1. Generate a strong random key:

```bash
# Linux/Mac
openssl rand -hex 32
# Output: a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

2. Add to `agent.yaml`:

```yaml
forwarder:
  backend_url: "https://siem.yourcompany.com:8443"
  api_key: "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
  # Do NOT set cert_file / key_file / ca_file
```

3. Configure the backend to validate the `X-API-Key` header against this value.

### Important notes for API key auth

- You still need HTTPS — use a valid server certificate on the backend
- If the backend uses a private CA, you still need `ca_file`:
  ```yaml
  forwarder:
    backend_url: "https://siem.yourcompany.com:8443"
    api_key: "your-key"
    ca_file: "certs/ca.crt"   # still needed to verify the server cert
  ```
- If the backend uses a public CA certificate (Let's Encrypt, DigiCert, etc.), you don't need `ca_file` at all — Go's built-in trust store handles verification

---

## Certificate Renewal

Certificates created with the commands above expire after 825 days (~2.25 years). Set a calendar reminder to renew them before expiry. The renewal process is:

```bash
# Generate new cert for an agent (same CA, new expiry)
AGENT="workstation-01"
openssl genrsa -out ${AGENT}-new.key 2048
openssl req -new -key ${AGENT}-new.key -out ${AGENT}-new.csr \
  -subj "/C=US/O=YourOrg/CN=${AGENT}"
openssl x509 -req -days 825 \
  -in ${AGENT}-new.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out ${AGENT}-new.crt
```

Then deploy the new `.crt` and `.key` to the host and restart the service:
```powershell
Restart-Service OpenSIEMAgent
```

---

## Troubleshooting TLS

### "x509: certificate signed by unknown authority"

The agent cannot verify the backend's server certificate. Causes:
- `ca_file` is not set in `agent.yaml`
- `ca_file` points to the wrong CA
- The backend certificate was not signed by the CA in `ca_file`

Fix: Make sure `ca_file` points to the CA that signed `server.crt`.

### "tls: failed to verify client certificate"

The backend rejected the agent's certificate. Causes:
- The agent cert was not signed by the CA the backend trusts
- The agent cert has expired

Fix: Re-issue the agent certificate using the same CA the backend trusts.

### "connection refused" or timeout

The agent cannot reach the backend at all. Check:
- The backend is running and listening on the correct port
- Firewall allows outbound TCP from the agent to the backend port
- `backend_url` hostname resolves from the Windows host: `Resolve-DnsName siem.yourcompany.com`

### "certificate has expired"

Check expiry:
```bash
openssl x509 -in agent.crt -noout -dates
```

Issue a new certificate and redeploy.

### Running in debug mode to see TLS errors

Set `log.level: "debug"` in `agent.yaml` and run interactively:
```powershell
.\agent.exe -config agent.yaml
```

TLS errors will appear in the forwarder output.
