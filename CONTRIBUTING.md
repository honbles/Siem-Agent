# Contributing to ObsidianWatch Agent

Thank you for your interest in contributing. This document covers how to set up a development environment, the project conventions, and how to submit a change.

---

## Development Setup

```bash
git clone https://github.com/honbles/Seim-Agent.git
cd Siem-Agent
go mod tidy

# Verify everything compiles (run from repo root)
go build ./...

# Run tests
go test ./...

# Cross-compile for Windows from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o agent.exe ./cmd/agent
```

> **Note:** Most collector files carry a `//go:build windows` constraint because they use Windows-only syscalls (`wevtapi.dll`, `iphlpapi.dll`, ETW, etc.). `go build ./...` still compile-checks all packages regardless of the platform you run it on.

> **Important:** The `//go:build windows` directive **must be the absolute first line** of the file — before `package`, before any comments. A misplaced directive causes a compiler error.

---

## Project Layout

```
agent/
├── cmd/agent/main.go            # Entry point and collector wiring
├── internal/collector/          # One file per event source
├── internal/parser/             # Normalizer and enricher
├── internal/forwarder/          # HTTP forwarder, disk queue, retry
├── internal/config/             # YAML config loader
└── pkg/schema/event.go          # Shared Event / Batch types
```

---

## Adding a New Collector

1. Create `internal/collector/yourcollector.go` with `//go:build windows` as the first line.
2. Define a struct with at minimum `agentID`, `host string`, `out chan<- schema.Event`, and `*slog.Logger`.
3. Implement `Run(ctx context.Context) error` — block until `ctx` is cancelled.
4. Always send to the output channel with a non-blocking guard:
   ```go
   select {
   case c.out <- ev:
   default:
       c.logger.Warn("yourcollector: out channel full, dropping event")
   }
   ```
5. Add a config struct to `internal/config/config.go` under `CollectorConfig` with an `Enabled bool` field.
6. Add the config section to `configs/agent.yaml` with sensible defaults and comments.
7. Wire the collector in `cmd/agent/main.go` inside the `run()` function, appending its name to `activeCollectors`.
8. If the collector introduces a new `EventType`, add the constant to `pkg/schema/event.go`.

---

## Adding a New Event Type

Edit `pkg/schema/event.go` and add to the const block:

```go
const (
    // existing types ...
    EventTypeYourType EventType = "yourtype"
)
```

Then add classification logic in `internal/parser/normalizer.go`:
- `classifyByEventID()` — map Windows Event IDs to your new type
- `adjustSeverityByEventID()` — assign severity overrides for specific Event IDs

---

## Code Style

- Format with `gofmt -w .` before committing — unformatted code will not be merged.
- All exported types and functions must have a doc comment.
- Use `slog` for all logging at the appropriate level:
  - `Debug` — per-event detail, field values, parsing steps
  - `Info` — collector start/stop, service lifecycle
  - `Warn` — recoverable errors (channel full, single event parse failure)
  - `Error` — fatal collector failures that cause `Run()` to return
- Group imports: stdlib → external packages → internal (`obsidianwatch/agent/...`).
- Do not use `panic` in collectors — return errors or log and continue.

---

## Pull Request Process

1. Open an issue first for any significant change so the approach can be discussed before you invest time writing it.
2. Fork the repo and create a feature branch: `git checkout -b feat/your-feature`.
3. Keep commits focused — one logical change per commit with a descriptive message.
4. Update `configs/agent.yaml` and `README.md` if your change adds or modifies any configuration.
5. Run `go build ./...` and `go test ./...` before pushing — PRs that do not compile will not be reviewed.
6. Open the pull request against `main` with a clear description of what changed and why.

---

## Good First Issues

- Write unit tests for `internal/parser/normalizer.go` and `internal/parser/enricher.go`
- Add a `--dry-run` flag that prints events to stdout instead of forwarding to the backend
- Add IPv6 support to the network collector (`GetExtendedTcpTable` with `AF_INET6`)
- Add a Sysmon configuration template (`configs/sysmon-config.xml`) with recommended settings
- Write a PowerShell deployment script that copies the binary and config to remote hosts over WinRM
- Add SHA-256 file hashing to the FIM collector on create/modify events
- Add applog include/exclude filter patterns (only ship lines matching a regex)

---

## Reporting Bugs

Open a GitHub issue with:

- Windows version (`winver` output)
- Go version (`go version` output)
- The relevant section of `agent.yaml` (redact any keys or URLs)
- Log output around the error — set `log.level: debug` for full detail
- Steps to reproduce

---

## License

By contributing you agree that your contributions will be licensed under the [MIT License](LICENSE).
