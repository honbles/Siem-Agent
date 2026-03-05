# Contributing to OpenSIEM

Thank you for your interest in contributing. OpenSIEM is an early-stage open source project and contributions of all kinds are welcome — code, documentation, bug reports, and ideas.

---

## Before you start

- Open an **issue** before working on a large feature or refactor so we can discuss the approach and avoid duplicated effort
- For small bug fixes, typos, or documentation improvements — just open a PR directly

---

## Development setup

```bash
git clone https://github.com/YOUR_ORG/opensiem.git
cd opensiem/agent

# Download dependencies
go mod tidy

# Run tests
go test ./...

# Build for Windows from Linux/Mac
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent

# Build and run on Windows
go build -o agent.exe ./cmd/agent
.\agent.exe -config configs\agent.yaml
```

**Requirements:** Go 1.22+. No other tools needed.

---

## Good first contributions

These are well-scoped tasks that don't require deep Windows internals knowledge:

- **Complete XML parsing in `eventlog.go`** — the raw XML from `EvtRender` is stored as-is in `RawXML`. Add proper XML parsing to extract `EventID`, `TimeCreated`, `Computer`, `UserID`, and `EventData` fields into the `rawWinEvent` struct.

- **Complete ETW process collector** — `process.go` has the session structure in place. Full Win32 interop to call `StartTrace`, `EnableTraceEx2`, `OpenTrace`, and `ProcessTrace` is needed. See comments in the file. The `github.com/bi-zone/etw` package is an option if you want to avoid raw CGO.

- **Add `--dry-run` flag** — print events as JSON to stdout instead of forwarding to the backend. Useful for testing collector configuration without a backend.

- **Add a `--validate-config` flag** — load and validate `agent.yaml` then exit, reporting any errors. Useful for CI and deployment pipelines.

- **Write unit tests for the normalizer** — `internal/parser/normalizer.go` has no tests. Test EventID classification, severity adjustment, string sanitization, and truncation.

- **Write unit tests for the queue** — `internal/forwarder/queue.go` has no tests. Test Push/Pop ordering, eviction when full, recovery after a crash (queue files left on disk).

- **Add a Sysmon config template** — provide a recommended `sysmon-config.xml` in `configs/` or `docs/` that works well with OpenSIEM's event coverage.

- **Windows Firewall audit collector** — add a collector that reads from `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` to capture blocked connections.

---

## Code style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Keep files focused — one collector per file
- Add a comment block at the top of each new file explaining what it does (see existing files for the pattern)
- New collectors must implement `Run(ctx context.Context) error` and emit `schema.Event` values on a channel
- Use `//go:build windows` as the first line of any file that uses Windows-specific APIs
- Do not introduce new external dependencies without discussing in an issue first — the goal is to keep the dependency footprint minimal

---

## Submitting a PR

1. Fork the repo and create a branch: `git checkout -b feature/your-feature`
2. Make your changes
3. Run `go test ./...` and `go vet ./...` — both must pass
4. Run `GOOS=windows GOARCH=amd64 go build ./cmd/agent` — must compile without errors
5. Commit with a clear message: `feat: add XML parsing for EventLog collector`
6. Push and open a PR against `main`

---

## Reporting bugs

Open a GitHub issue with:

- Windows version (`winver` or `[System.Environment]::OSVersion`)
- Go version (`go version`)
- The relevant section of `agent.yaml` (redact any secrets)
- The log output around the error (set `log.level: debug`)
- What you expected to happen vs. what actually happened
