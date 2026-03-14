# SentinelSIEM

A proof-of-concept Security Information & Event Management platform built in Go, backed by Elasticsearch. Designed as the central detection and investigation brain for the Sentinel security portfolio.

## What It Does

SentinelSIEM ingests telemetry from multiple security sources, normalizes events to the Elastic Common Schema (ECS), evaluates Sigma detection rules in real time, and provides a query interface for threat hunting — all through a React-based dashboard with built-in case management.

### Data Sources

| Source | Protocol | Description |
|--------|----------|-------------|
| SentinelEDR | JSON/HTTP | Endpoint behavior telemetry (process, network, registry, file events) |
| Sentinel AV | JSON/HTTP | Malware scan results, quarantine actions, real-time blocks |
| Sentinel DLP | JSON/HTTP | Data classification, policy violations, removable media events |
| Windows Event Logs | WEF/HTTP | Security, Sysmon, and system events via XML or Winlogbeat JSON |
| Syslog | TCP/UDP/TLS | Firewalls, Linux auditd, network devices (RFC 5424 & 3164) |

### Detection Engine

- **Sigma rules** — Native parsing and evaluation of the open-standard YAML detection format
- **Single-event rules** — Field matching with full modifier support (`contains`, `re`, `cidr`, `base64`, `all`, etc.)
- **Correlation rules** — Multi-event patterns: `event_count` (threshold), `value_count` (distinct values), `temporal` (ordered sequences within time windows)
- **Cross-portfolio detections** — Rules that correlate across EDR + AV + DLP sources to detect multi-stage attack chains
- **Hot-reload** — File watcher + CLI trigger for zero-downtime rule updates

### Case Management

Built-in incident response workflow: alert escalation, observable extraction (IPs, hashes, domains, usernames), analyst collaboration via timeline, MITRE ATT&CK tagging, and resolution tracking with detection efficacy metrics (MTTD/MTTR).

## Architecture

```
[SentinelEDR]  ─┐
[Sentinel AV]  ─┤
[Sentinel DLP] ─┤─→ [sentinel-ingest] → [sentinel-normalize] → [sentinel-store (ES)]
[Windows WEF]  ─┤                                ↓
[Syslog]       ─┘                       [sentinel-correlate]
                                                 ↓
                                        [alerts + cases in ES]
                                                 ↓
                                        [sentinel-query / dashboard]
```

| Component | Description |
|-----------|-------------|
| `sentinel-ingest` | HTTP/syslog listener, API key auth, NDJSON batch support |
| `sentinel-normalize` | ECS normalization engine with per-source-type parsers |
| `sentinel-store` | Elasticsearch client — index templates, ILM, bulk indexing |
| `sentinel-correlate` | Real-time Sigma rule engine with correlation state management |
| `sentinel-query` | REST API server, query language → ES DSL translation, serves dashboard |
| `sentinel-cli` | Management CLI for rules, sources, keys, health, and ad-hoc queries |
| `sentinel-dashboard` | React SPA — alert triage, cases, threat hunting, rule management, source health |

## Project Structure

```
├── cmd/
│   ├── sentinel-ingest/       # HTTP ingestion server
│   ├── sentinel-correlate/    # Sigma rule evaluation engine
│   ├── sentinel-query/        # Query API + dashboard server
│   └── sentinel-cli/          # Management CLI
├── internal/
│   ├── common/                # Shared types (ECS event, auth, metrics)
│   ├── config/                # TOML config loading
│   ├── store/                 # Elasticsearch client wrapper
│   ├── ingest/                # HTTP/syslog listeners, pipeline
│   ├── normalize/parsers/     # Per-source-type ECS parsers
│   ├── correlate/             # Sigma rule engine + correlation state
│   ├── query/                 # Query parser, ES translator, REST API
│   ├── cases/                 # Case management service
│   ├── sources/               # Source configuration + snippets
│   └── alert/                 # Alert pipeline
├── rules/                     # Sigma detection rules
├── parsers/                   # Logsource maps + syslog sub-parser configs
├── web/                       # React dashboard
├── scripts/                   # Helper scripts (ES wait, cert gen)
└── tests/                     # Integration + benchmark tests
```

## Tech Stack

**Backend:** Go 1.22+ with `go-elasticsearch`, `chi` (routing), `zap` (logging), `gopkg.in/yaml.v3`

**Storage:** Elasticsearch 8.x with ECS-compliant index templates and ILM policies

**Frontend:** React, Tailwind CSS, TanStack Table + Query, Recharts, Nivo (ATT&CK heatmap), CodeMirror 6 (query editor), Zustand, Headless UI

## Getting Started

### Prerequisites

- Go 1.22+
- Docker & Docker Compose (for Elasticsearch)
- Node.js 18+ (for dashboard development)
- Make

### Build

```bash
make build       # Compiles all binaries to bin/
make test        # Runs tests
make lint        # Runs go vet
```

### Run

```bash
docker-compose up -d          # Start Elasticsearch
make run-ingest               # Start ingestion server
make run-correlate            # Start correlation engine
make run-query                # Start query API + dashboard
```

## Implementation Phases

| Phase | Description | Tasks | Depends On | Status |
|-------|-------------|-------|------------|--------|
| P0 | Scaffolding — Go module, Docker Compose, ECS structs, config, ES client | 5 | — | In Progress |
| P1 | HTTP Ingestion + SentinelEDR Parser | 4 | P0 | Pending |
| P1a | Sentinel AV & DLP Parsers + Cross-Portfolio Rules | 4 | P1 | Pending |
| P2 | Windows Event Log Ingestion (XML + Winlogbeat JSON) | 4 | P1 | Pending |
| P3 | Syslog Ingestion (TCP/UDP/TLS, RFC 5424 & 3164) | 4 | P1 | Pending |
| P4 | Sigma Single-Event Detection Engine | 5 | P1 | Pending |
| P5 | Sigma Correlation Rules (event_count, value_count, temporal) | 5 | P4 | Pending |
| P6 | Query Language + REST API | 4 | P0, P1 | Pending |
| P7 | React Dashboard + Source Configuration | 10 | P6 | Pending |
| P8 | CLI Management Tool | 4 | P0–P7 | Pending |
| P9 | Case Management (escalation, observables, timeline) | 7 | P4, P7 | Pending |
| P10 | Integration Tests (55 rules, 700 events, cross-source correlation) | 5 | All | Pending |
| P11 | Hardening (metrics, load test, DLQ, graceful shutdown) | 4 | All | Pending |

See `REQUIREMENTS.md` for the full specification and task breakdown.

## License

Proprietary — Sentinel Security Portfolio.
