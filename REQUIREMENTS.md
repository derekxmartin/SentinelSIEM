# Akeso SIEM — Requirements Document v2.4
## A Proof-of-Concept Security Information & Event Management Platform
**Version 2.4 — Claude Code Implementation Phases | March 2026**

Built on Go + Elasticsearch with native Sigma rule support and ECS normalization. Designed to ingest telemetry from AkesoEDR, AkesoAV, AkesoDLP, and AkesoNDR. React-based dashboard with built-in case management, user authentication with MFA, and AI-powered investigation assistant.

> **v2.4 Changelog (from v2.3):** Added dashboard authentication: local user accounts in ES, bcrypt password hashing, JWT sessions (access + refresh tokens), TOTP MFA with Google Authenticator/Authy compatibility, login/logout pages, auth guard on all routes, user profile in Settings, CLI user management. Case management now attributes all actions to authenticated users. Added Playwright headless browser E2E test suite for all dashboard workflows. Added global search with universal entity search (type-aware across events/alerts/cases/host-scores/rules) and command palette (`Cmd+Shift+P`). Added global time range picker specification (shared component with Hunt page, Zustand state propagation). Added file-based structured server logging with rotation (P11-T6). 7 new tasks in Phase 7 (P7-T11 through P7-T17), 1 new task in Phase 11 (P11-T6). Total: +8 tasks (86 → 94).
>
> **v2.3 Changelog (from v2.2):** Added test data generation infrastructure: static fixture files for all 6 source types (P0-T6), Python scenario generator CLI with 8 attack narratives and noise profiles (P1-T5), full 50K+ event demo dataset with `make demo` validation (P10-T0), deployment automation with `make install`/`make dev`/`make demo`/`make clean` targets (P11-T5). Total: +4 tasks (82 → 86).
>
> **v2.2 Changelog (from v2.1):** Added AkesoNDR as ingestion source (Section 4.7), added `ndr.*`/`dns.*`/`tls.*`/`smb.*`/`kerberos.*`/`ssh.*` ECS extension fields (Section 3.3), added 5 NDR cross-portfolio Sigma correlation rules (Section 5.3), added Phase 1b for NDR parser implementation (5 tasks), updated Phase 10 integration tests for 6 source types (2 new tasks), updated AI assistant tools and capabilities for NDR context, updated source onboarding for NDR, updated dashboard for NDR host score surfacing.

---

# PART I: REQUIREMENTS & ARCHITECTURE

## 1. Executive Summary

Akeso SIEM is a proof-of-concept Security Information and Event Management platform built in Go, backed by Elasticsearch for storage and search. Its purpose is to provide a centralized detection and investigation platform that ingests telemetry from the entire Akeso portfolio — AkesoEDR, AkesoAV, AkesoDLP, and AkesoNDR — as well as Windows Event Logs and syslog sources, normalizes events into the Elastic Common Schema (ECS), evaluates Sigma detection rules in real time, and exposes a query interface for threat hunting.

The project is the central brain of the Akeso portfolio. Where AkesoEDR generates endpoint behavior telemetry, AkesoAV generates malware scan and quarantine events, AkesoDLP generates data classification and policy violation events, and AkesoNDR generates network traffic metadata, behavioral detections, and host threat scores, AkesoSIEM is the cross-host, cross-source, cross-product correlator that unifies all of them into a single detection and investigation platform. Together they cover the full security stack: endpoint behavior (EDR) + malware detection (AV) + data protection (DLP) + network visibility (NDR) + log aggregation (SIEM) → correlation → alerting → investigation.

Akeso SIEM natively consumes Sigma rules — the open-standard YAML-based detection format used by thousands of detection engineers worldwide. This means the platform ships with access to 3000+ community-written detections from the SigmaHQ repository and is interoperable with real-world detection engineering workflows.

The platform includes a built-in case management module for alert escalation and incident response, eliminating external dependencies on third-party tools like TheHive. An AI investigation assistant powered by the Anthropic API provides natural language query assistance, alert triage summaries, multi-step investigation workflows, detection rule drafting, and cross-portfolio attack narratives.

## 2. Project Goals & Non-Goals

### 2.1 Goals

- Build a working SIEM that ingests events from the full Akeso portfolio (AkesoEDR, AkesoAV, AkesoDLP, AkesoNDR) plus Windows Event Logs and syslog, normalizes them to ECS, stores them in Elasticsearch, and evaluates Sigma rules in real time.
- Support native Sigma rule loading, parsing, and evaluation — including single-event rules and Sigma correlation rules (multi-event sequences, thresholds, temporal proximity).
- Provide a query interface for ad-hoc threat hunting over stored events using a simplified query language that translates to Elasticsearch DSL.
- Provide built-in case management for alert escalation, observable tracking, analyst collaboration, and incident resolution.
- Generate a React-based web dashboard for alert triage, event exploration, case management, source onboarding, and system health monitoring.
- Provide user authentication with JWT sessions, TOTP-based MFA, and analyst identity attribution across case management, alert triage, and AI assistant actions.
- Provide an AI-powered investigation assistant that leverages the SIEM's REST API to assist analysts with natural language queries, alert triage, multi-step investigations, detection rule drafting, and cross-portfolio attack narrative generation.
- Surface AkesoNDR host threat scores alongside alerts and cases to provide network-layer risk context for investigation prioritization.
- Maintain a clean Go codebase with minimal external dependencies, buildable with standard Go tooling.

### 2.2 Non-Goals (v1)

- Replacing Splunk, Elastic Security, or any production SIEM. This is a learning and portfolio tool.
- Machine learning or behavioral analytics. v1 is rule-based only.
- Multi-tenant or multi-cluster Elasticsearch deployments.
- Agent deployment on endpoints (AkesoEDR is the agent, AkesoNDR is the network sensor — Akeso SIEM is the server).
- SOAR (Security Orchestration, Automation, and Response) beyond basic case management.

## 3. System Architecture

### 3.1 Component Overview

| Component | Language | Responsibility |
|-----------|----------|----------------|
| akeso-ingest | Go | Receives events from all sources (HTTP, syslog, WEF). Parses, normalizes to ECS, and forwards to the pipeline. |
| akeso-normalize | Go | Normalization engine with per-source-type parsers. Maps raw event fields to ECS field names and types. |
| akeso-store | Go | Elasticsearch client. Manages index templates, ILM policies, and bulk indexing. |
| akeso-correlate | Go | Real-time Sigma rule engine. Evaluates events against loaded rules. Fires alerts on matches. Maintains state for correlation rules. |
| akeso-query | Go | Query API server. Translates simplified query syntax to Elasticsearch DSL. Serves the web dashboard and case management API. |
| akeso-cli | Go | Management CLI for rule loading, source management, system health, and ad-hoc queries. |
| akeso-dashboard | React | Single-page web dashboard for alert triage, case management, event search, source health, source onboarding, and rule management. Includes AI investigation assistant panel. Served by akeso-query. |

### 3.2 Data Flow

```
[AkesoEDR] ──JSON/HTTP──→
[AkesoAV]  ──JSON/HTTP──→
[AkesoDLP] ──JSON/HTTP──→
[AkesoNDR] ──JSON/HTTP──→  [akeso-ingest] → [akeso-normalize] → [akeso-store (ES)]
[Windows Event Logs] ──WEF/HTTP──→                          ↓ (real-time stream)
[Syslog sources] ──syslog/TCP──→                   [akeso-correlate]
                                                            ↓ (alerts)
                                                   [akeso-cases index in ES] + [alert index in ES]
                                                            ↓
                                                   [akeso-dashboard / akeso-query]
```

### 3.3 Normalization — Elastic Common Schema (ECS)

All events are normalized to ECS before storage. ECS provides a common field schema so that a single Sigma rule can match events from any source. Key ECS field groups used:

- `event.*`: event.kind, event.category, event.type, event.action, event.outcome, event.severity
- `process.*`: process.pid, process.name, process.executable, process.command_line, process.parent.*
- `source.* / destination.*`: IP, port, domain, user for network events
- `user.*`: user.name, user.domain, user.id
- `host.*`: host.name, host.ip, host.os.*
- `file.*`: file.name, file.path, file.hash.*, file.size
- `registry.*`: registry.key, registry.value, registry.data.*
- `network.*`: network.protocol, network.direction, network.bytes
- `threat.*`: threat.technique.id, threat.technique.name (MITRE ATT&CK mapping)
- `dlp.*`: dlp.policy.name, dlp.policy.action, dlp.classification, dlp.channel (custom extension for DLP events)
- `av.*`: av.scan.result, av.scan.engine, av.signature.name, av.action (custom extension for AV events)
- `dns.*`: dns.question.name, dns.question.type, dns.answers.data, dns.response_code, dns.header_flags (populated by NDR DNS metadata)
- `http.*`: http.request.method, http.response.status_code, http.response.body.bytes, url.full, user_agent.original (populated by NDR HTTP metadata)
- `tls.*`: tls.version, tls.cipher, tls.client.ja3, tls.server.ja3s, tls.client.server_name (SNI), tls.client.ja4, tls.server.ja4s (populated by NDR TLS metadata)
- `smb.*`: smb.version, smb.action, smb.filename, smb.path, smb.domain, smb.username (custom extension for NDR SMB events)
- `kerberos.*`: kerberos.request_type, kerberos.client, kerberos.service, kerberos.cipher, kerberos.success, kerberos.error_code (custom extension for NDR Kerberos events)
- `ssh.*`: ssh.client, ssh.server, ssh.hassh, ssh.hassh_server (populated by NDR SSH metadata)
- `ndr.*`: ndr.detection.name, ndr.detection.severity, ndr.host_score.threat, ndr.host_score.certainty, ndr.host_score.quadrant, ndr.beacon.interval_mean, ndr.beacon.interval_stddev, ndr.session.conn_state, ndr.session.community_id (custom extension for NDR events)

Each source type gets a dedicated parser that maps its native fields to ECS. For example, AkesoEDR's `AKESO_EVENT` with source `drv:process_create` maps to ECS `event.category: process`, `event.type: start`, `process.pid`, `process.executable`, etc.

Akeso AV scan events map to `event.category: malware` with `file.*`, `av.*`, and `threat.*` fields. Akeso DLP violation events map to `event.category: file` with `file.*`, `user.*`, `dlp.*`, and `event.action: violation`.

AkesoNDR events arrive pre-normalized to ECS but use several mapping patterns: `ndr:session` events map to `event.category: network_connection` with `source.*`, `destination.*`, `network.*`, and `ndr.session.*` fields. Protocol-specific events (`ndr:dns`, `ndr:http`, `ndr:tls`, `ndr:smb`, `ndr:kerberos`, etc.) map to their respective ECS field groups (`dns.*`, `http.*`, `tls.*`, etc.) plus `network.*`. Detection events (`ndr:detection`) map to `event.category: intrusion_detection` with `threat.*` MITRE mapping and `ndr.detection.*` fields. Host score events (`ndr:host_score`) are indexed as `event.category: host` with `ndr.host_score.*` fields for dashboard surfacing and correlation enrichment.

### 3.4 Sigma Rule Engine

The correlation engine natively loads and evaluates Sigma rules. Sigma rules are YAML files that describe detection logic in a vendor-neutral format. The engine supports:

- **Single-event rules:** Match field conditions on individual events (selection + condition logic with AND/OR/NOT).
- **Sigma correlation rules (Sigma 2.0 spec):** Multi-event patterns including event_count (threshold), value_count (distinct values), and temporal (ordered sequence within a time window).
- **Logsource mapping:** Sigma's logsource (category/product/service) maps to ECS field filters so rules target the correct event subset.
- **Modifier support:** `contains`, `startswith`, `endswith`, `re` (regex), `base64`, `cidr`, `all`, etc.

Rules are loaded from a configurable directory (Git-managed, same pattern as AkesoEDR) with hot-reload support.

The logsource mapping table includes `product: akeso_ndr` which routes to NDR events. NDR protocol-specific events support **dual logsource matching**: `ndr:dns` events match both `product: akeso_ndr` AND `category: dns`, meaning community SigmaHQ network detection rules (e.g., DNS rules targeting `dns.question.name`) automatically evaluate against NDR DNS metadata without modification. Same pattern applies for `ndr:http` → `category: web`, `ndr:tls` → `category: tls`, `ndr:smb` → `category: smb`, `ndr:kerberos` → `category: kerberos`.

### 3.5 Case Management Module

When a Sigma rule fires, the alert is indexed in Elasticsearch for dashboard display. Analysts can escalate alerts to cases via the built-in case management module. The escalation pipeline automatically extracts observables (IPs, hashes, usernames, domains, process names, JA3/JA4 fingerprints, Community IDs, SNI values) from linked events, inherits severity from the highest-severity alert, and auto-tags with MITRE ATT&CK techniques from the triggering Sigma rules. For cross-portfolio alerts involving NDR events, observables include network-layer evidence and the NDR host threat score is attached to the case for risk context.

Cases follow a defined workflow: New → In Progress → Resolved → Closed. Analysts can merge multiple related alerts into a single case, add comments, manually add observables for analyst-discovered IOCs, and close cases with a required resolution type (true_positive, false_positive, benign, duplicate). All analyst actions are logged to a case timeline with the authenticated user's identity for audit and collaboration.

Closed cases with `resolution_type = true_positive` contribute to detection efficacy metrics (MTTD, MTTR) displayed on the Overview dashboard.

#### 3.5.1 Case Data Model

Cases are stored in Elasticsearch in the `akeso-cases-{date}` index. Each case document contains:

- `case.id` — Unique case identifier (UUID).
- `case.title` — Human-readable title (auto-generated from triggering rule or manually set).
- `case.status` — Workflow state: `new`, `in_progress`, `resolved`, `closed`.
- `case.severity` — Critical, High, Medium, Low (inherited from highest-severity linked alert).
- `case.assignee` — Analyst username or `unassigned`.
- `case.alert_ids[]` — Array of linked alert document IDs. Multiple alerts can be merged into one case.
- `case.observables[]` — Extracted entities: IPs, hashes, domains, usernames, process names. Each observable has a `type`, `value`, `source` (which alert/event), and optional `tags`.
- `case.timeline[]` — Analyst activity log: comments, status changes, observable additions, alert merges. Each entry has `timestamp`, `author`, `action_type`, and `content`.
- `case.tags[]` — Free-form tags plus auto-populated MITRE ATT&CK technique IDs from linked alerts.
- `case.resolution` — Required on close: `true_positive`, `false_positive`, `benign`, `duplicate`. Includes optional `resolution_notes` free-text field.
- `case.created_at`, `case.updated_at`, `case.closed_at` — Lifecycle timestamps.

#### 3.5.2 Alert-to-Case Escalation

When an analyst clicks "Escalate" on an alert (or selects multiple alerts for bulk escalation), the system:

1. Creates a new case with title derived from the rule name and primary entity (e.g., "Credential Theft — user jsmith on HOST-042").
2. Links all selected alert IDs to the case.
3. Runs the observable extractor against all linked events to auto-populate IPs, hashes, usernames, domains, and process names.
4. Inherits severity from the highest-severity linked alert.
5. Auto-tags with MITRE ATT&CK techniques from the triggering Sigma rules.
6. Updates the alert status to "Escalated" with a back-reference to the case ID.

### 3.6 Elasticsearch Index Strategy

- **Events:** `akeso-events-{source_type}-{date}` — daily indices per source type for efficient retention and search scoping.
- **Alerts:** `akeso-alerts-{date}` — alert documents with references to triggering event IDs.
- **Cases:** `akeso-cases-{date}` — case documents with linked alert IDs, observables, and timeline entries. 365-day retention matching alert retention.
- **Sources:** `akeso-sources` — source configuration documents (not date-rotated, low-volume config store).
- **Users:** `akeso-users` — user accounts (username, display_name, password_hash, mfa_secret, mfa_enabled). Not date-rotated.
- **Sessions:** `akeso-sessions` — refresh token records with user_id, issued_at, expires_at, revoked flag. TTL-based cleanup.
- **NDR Host Scores:** `akeso-ndr-host-scores` — latest-only per host IP, upserted from `ndr:host_score` events. Not date-rotated. Used by dashboard for NDR risk context display.
- **Index templates:** ECS-compliant field mappings applied automatically to new indices. Includes all `ndr.*`, `dns.*`, `http.*`, `tls.*`, `smb.*`, `kerberos.*`, and `ssh.*` custom extension field mappings.
- **ILM (Index Lifecycle Management):** Hot → warm → delete policy with configurable retention (default 90 days for events, 30 days for `ndr:session` events due to volume, 365 for alerts and cases).

## 4. Ingestion Sources

### 4.1 AkesoEDR (JSON/HTTP)

| Aspect | Requirement |
|--------|-------------|
| Protocol | HTTP POST to `/api/v1/ingest` with JSON body. TLS optional for v1. |
| Authentication | API key in `X-API-Key` header. Keys managed via CLI. |
| Event format | `AKESO_EVENT` JSON as emitted by the AkesoEDR agent's JSON writer. |
| ECS mapping | Per-sensor-type mapper: `drv:process_create` → `event.category: process`, `hook:NtProtectVirtualMemory` → `event.category: process, event.type: change`, etc. |
| Batch support | Accept NDJSON (newline-delimited JSON) for bulk ingestion. |

### 4.2 Windows Event Logs (WEF/HTTP)

| Aspect | Requirement |
|--------|-------------|
| Protocol | HTTP POST with XML or JSON-rendered Windows Events. Compatible with WEF via HTTP collector or Winlogbeat-style JSON. |
| Key event IDs | 4624/4625 (logon), 4648 (explicit creds), 4768/4769 (Kerberos), 4688 (process creation), 7045 (service install), 1/3/7/8/10/11/12/13 (Sysmon). |
| ECS mapping | XML field paths → ECS fields. Sysmon events get dedicated parsers. |
| Sigma compatibility | Logsource `product: windows, service: security/sysmon/system` must map correctly so SigmaHQ Windows rules work out of the box. |

### 4.3 Syslog (TCP/UDP/TLS)

| Aspect | Requirement |
|--------|-------------|
| Protocol | Syslog over TCP (preferred), UDP (legacy), and TLS (secure). RFC 5424 and RFC 3164 formats. |
| Sources | Firewalls (pfSense, iptables), network devices, Linux auditd, application logs. |
| Parsing | Configurable syslog parser chain: extract envelope, then apply per-device regex/KV sub-parsers. |
| ECS mapping | Syslog fields → `observer.*` (for network devices), `host.*` (for hosts), `event.*` (for metadata). |

### 4.4 Akeso AV (JSON/HTTP)

| Aspect | Requirement |
|--------|-------------|
| Protocol | HTTP POST to `/api/v1/ingest` with JSON body (same endpoint as AkesoEDR, differentiated by `source_type` field). |
| Authentication | API key in `X-API-Key` header. |
| Event types | `av:scan_result` (file scanned, verdict clean/malicious/suspicious, matched signature name), `av:quarantine` (file moved to quarantine vault, original path, hash, rule), `av:realtime_block` (on-access scan blocked execution), `av:signature_update` (signature DB updated, version, count), `av:scan_error` (scan failed, reason). |
| ECS mapping | `av:scan_result` → `event.category: malware`, `event.type: info`, `file.path`, `file.hash.*`, `file.size`, `av.scan.result`, `av.signature.name`, `threat.indicator.type: file`. `av:quarantine` → `event.category: malware`, `event.type: deletion`, `event.action: quarantine`, `file.*`. `av:realtime_block` → `event.category: malware`, `event.type: denied`, `process.*` (blocked process), `file.*`. |
| Sigma compatibility | Logsource `product: akeso_av` maps to AV events. Custom Sigma rules can target `av.scan.result = "malicious"` or `av.signature.name contains "Mimikatz"`. |

### 4.5 Akeso DLP (JSON/HTTP)

| Aspect | Requirement |
|--------|-------------|
| Protocol | HTTP POST to `/api/v1/ingest` with JSON body. |
| Authentication | API key in `X-API-Key` header. |
| Event types | `dlp:policy_violation` (sensitive data detected, policy name, classification level, channel, action taken), `dlp:classification` (file classified, label assigned), `dlp:block` (data transfer blocked by policy), `dlp:audit` (sensitive data access logged but allowed), `dlp:removable_media` (data written to USB/external drive). |
| ECS mapping | `dlp:policy_violation` → `event.category: file`, `event.type: access`, `event.action: violation`, `file.*`, `user.*`, `dlp.policy.name`, `dlp.policy.action`, `dlp.classification`, `dlp.channel` (email/upload/usb/print/share). `dlp:block` → `event.category: file`, `event.type: denied`, same fields + `event.outcome: failure`. `dlp:removable_media` → `event.category: file`, `event.type: creation`, `destination.address` (device ID). |
| Sigma compatibility | Logsource `product: akeso_dlp` maps to DLP events. Rules can target `dlp.classification = "confidential" AND dlp.channel = "usb"` or correlate with EDR events. |

### 4.7 AkesoNDR (JSON/HTTP)

| Aspect | Requirement |
|--------|-------------|
| Protocol | HTTP POST to `/api/v1/ingest` with JSON body (same endpoint as all Akeso products, differentiated by `source_type: akeso_ndr`). |
| Authentication | API key in `X-API-Key` header. |
| Event types | `ndr:session` (TCP/UDP connection metadata: 5-tuple, duration, bytes, packets, conn_state, community_id), `ndr:dns` (DNS query/response metadata with entropy scoring), `ndr:http` (HTTP request/response metadata), `ndr:tls` (TLS handshake metadata with JA3/JA4 fingerprints, certificate fields, SNI), `ndr:smb` (SMB file operations, authentication, tree connects), `ndr:kerberos` (Kerberos AS/TGS requests with encryption types, principals, errors), `ndr:ssh` (SSH version exchange, HASSH fingerprints), `ndr:smtp` (SMTP envelope and header metadata), `ndr:rdp` (RDP negotiation metadata), `ndr:ntlm` (NTLM authentication metadata), `ndr:ldap` (LDAP bind/search metadata), `ndr:dcerpc` (DCE-RPC endpoint/operation metadata), `ndr:detection` (behavioral detection alert with MITRE mapping, severity, certainty, PCAP reference), `ndr:signature` (Suricata rule match alert), `ndr:host_score` (per-host threat/certainty score with quadrant classification). |
| ECS mapping | NDR events arrive pre-normalized to ECS by the AkesoNDR export pipeline. The SIEM parser validates ECS field presence, adds `event.ingested` timestamp, tags `source_type: akeso_ndr`, and ensures custom extension fields (`ndr.*`, `smb.*`, `kerberos.*`, `ssh.*`) are correctly indexed. `ndr:session` → `event.category: network_connection`, `source.*`, `destination.*`, `network.*`, `ndr.session.*`. `ndr:dns` → `event.category: network` + `dns.*`. `ndr:detection` → `event.category: intrusion_detection`, `threat.*`, `ndr.detection.*`. `ndr:host_score` → `event.category: host`, `ndr.host_score.*` (upserted to dedicated index). |
| Batch support | NDJSON. NDR exports in batches of 500 events or 5s flush. |
| Sigma compatibility | Logsource `product: akeso_ndr` maps to all NDR events. NDR protocol events support **dual logsource matching**: `ndr:dns` events match both `product: akeso_ndr` AND `category: dns`, `ndr:http` matches `category: web`, etc. Community SigmaHQ network rules automatically evaluate against NDR metadata. |
| Community ID | All `ndr:session` and protocol events include `network.community_id` (Community ID v1.0 spec). Enables cross-tool correlation with AkesoEDR and AkesoFW events sharing the same flow identifier. |
| Host scores | `ndr:host_score` events are indexed in both the standard time-series event index AND upserted to the dedicated `akeso-ndr-host-scores` index (latest-only per host IP). The dashboard queries this index to display NDR risk context alongside alerts and cases. |

### 4.8 Source Onboarding

Source onboarding is supported via both the CLI (`akeso-cli sources add`) and a guided wizard in the dashboard. The onboarding flow covers:

1. **Source type selection** — Card-based selector for AkesoEDR, AkesoAV, AkesoDLP, AkesoNDR, Windows Event Logs, Syslog (Firewall/Linux Host/Network Device/Custom).
2. **Type-specific configuration** — Source name, protocol, port, sub-parser selection (for syslog), expected host count. Auto-generates API key on completion.
3. **Configuration snippet generation** — Copy-paste config blocks tailored to the source type (TOML for Akeso agents, YAML for Winlogbeat, rsyslog conf for syslog, pfSense instructions for firewalls).
4. **Live verification** — Polls for first event from the newly configured source with real-time feedback. Shows parsed ECS fields on success or troubleshooting tips on timeout.

Source configurations are stored in the `akeso-sources` ES index and drive the Sources health page (expected vs. actual host counts, health status calculations, sub-parser assignments).

A **sub-parser test interface** is available from both the onboarding wizard and the Sources page, allowing admins to paste a sample log line, select a sub-parser, and see the parsed ECS output before deploying.

## 5. Detection Requirements

### 5.1 Sigma Single-Event Rules

The engine must correctly evaluate the full Sigma detection syntax: selections as YAML maps (AND) and lists (OR), conditions combining selections with boolean logic, and field modifiers (`contains`, `startswith`, `endswith`, `re`, `base64`, `cidr`, `all`, `windash`, `base64offset`).

### 5.2 Sigma Correlation Rules

The engine must support Sigma 2.0 correlation types: event_count (threshold), value_count (distinct values), and temporal (ordered sequence within a time window, correlated by a shared field).

### 5.3 Detection Content

- Ship with a curated subset of SigmaHQ rules (Windows process creation, authentication, persistence, lateral movement, credential access).
- Ship with custom Sigma rules for Akeso portfolio cross-source detections:
  - **EDR + AV:** "Process flagged by EDR for shellcode injection also has AV scan result of malicious" (confirms EDR behavioral detection with AV static detection).
  - **EDR + DLP:** "User whose workstation triggered an EDR credential theft alert accesses a file classified as confidential within 30 minutes" (credential compromise → data theft chain).
  - **AV + DLP:** "File quarantined by AV was previously flagged by DLP as containing sensitive data" (malware targeting sensitive documents).
  - **DLP + Windows Events:** "DLP detects sensitive file copy to USB on a machine where the user authenticated with a different account than usual" (compromised account exfiltrating data).
  - **Full chain:** "EDR detects lateral movement → AV detects dropped tool on target host → DLP detects sensitive file access on target host → EDR detects outbound data transfer" (complete attack lifecycle across all products).
  - **EDR + NDR: Credential Theft → Lateral Movement** — EDR detects LSASS access on Host A → NDR detects SMB lateral movement from Host A to Host B within 30 minutes, correlated by `source.ip`. Temporal correlation. MITRE: T1003 → T1021.002.
  - **NDR + EDR: Network Beacon → Process Identification** — NDR detects C2 beaconing to external IP → correlated with EDR process creation events on the beaconing host within 5 minutes to identify the responsible process. MITRE: T1071 → T1059.
  - **NDR + AV: Lateral Tool Transfer → Malware Detection** — NDR detects SMB file transfer to a new internal host → AV detects the transferred file as malicious on the destination host within 10 minutes, correlated by `destination.ip` and optionally `file.hash.*`. MITRE: T1570.
  - **NDR + DLP: Exfiltration Confirmation** — NDR detects high-volume outbound transfer from Host A → DLP previously classified files accessed on Host A as confidential within the preceding 60 minutes. Correlated by `host.ip` + `user.name`. MITRE: T1041.
  - **Full chain (with NDR):** "NDR port scan → EDR credential dumping → NDR SMB lateral movement → NDR data exfiltration" — 4-event temporal correlation spanning 3 Akeso products (NDR + EDR + NDR + NDR), correlated by `user.name` within 2 hours. MITRE: T1046 → T1003 → T1021.002 → T1041. This is the most complex detection in the portfolio.
- Git-based rule updates: `akeso-cli rules update` pulls from configured remotes, validates, hot-reloads.
- Rule tagging by MITRE ATT&CK technique for dashboard grouping.

## 6. Query & Hunting Interface

### 6.1 Query Language

A simplified query syntax that translates to Elasticsearch DSL: field-value matching (`process.name = "cmd.exe"`), wildcards, boolean logic (AND/OR/NOT), time ranges, aggregations (`count() by user.name where ...`), and pipe syntax for chaining (`... | sort @timestamp desc | limit 100`).

### 6.2 REST API

**Core endpoints:**
- `POST /api/v1/query` — execute query, return JSON results
- `GET /api/v1/alerts` — list alerts with filters
- `GET /api/v1/alerts/{id}` — alert detail with linked events
- `GET /api/v1/rules` — loaded Sigma rules
- `POST /api/v1/rules/reload` — trigger hot-reload
- `GET /api/v1/health` — system health (no auth required)

**Authentication endpoints:**
- `POST /api/v1/auth/login` — authenticate with username + password. Returns access_token or mfa_required flag.
- `POST /api/v1/auth/mfa` — complete MFA challenge with TOTP code. Returns access_token.
- `POST /api/v1/auth/refresh` — exchange refresh_token cookie for new access_token.
- `POST /api/v1/auth/logout` — revoke refresh_token.
- `GET /api/v1/auth/me` — current user profile (username, display_name, mfa_enabled).
- `PUT /api/v1/auth/me/password` — change password. Body: current_password, new_password.
- `POST /api/v1/auth/me/mfa/enroll` — begin MFA enrollment. Returns QR code URI.
- `POST /api/v1/auth/me/mfa/verify` — confirm MFA enrollment with TOTP code.
- `DELETE /api/v1/auth/me/mfa` — disable MFA. Requires current password.

**Case management endpoints:**
- `POST /api/v1/cases` — create a case (from escalation or manual). Body: title, severity, alert_ids[], tags[]. Returns case document with auto-extracted observables.
- `GET /api/v1/cases` — list cases with filters. Query params: status, severity, assignee, tag, date range. Paginated. Sortable by created_at, updated_at, severity.
- `GET /api/v1/cases/{id}` — case detail with full timeline. Returns case document, linked alerts (expanded), observables, and complete timeline.
- `PUT /api/v1/cases/{id}` — update case fields. Body: status, severity, assignee, title, tags. Status transitions validated. Resolution required for resolved/closed.
- `POST /api/v1/cases/{id}/merge` — merge additional alerts into case. Body: alert_ids[]. Adds alerts, extracts new observables, deduplicates, logs merge to timeline.
- `POST /api/v1/cases/{id}/comments` — add analyst comment to timeline. Body: content (markdown). Logged with author and timestamp.
- `POST /api/v1/cases/{id}/observables` — manually add observable. Body: type (ip/hash/domain/user/process), value, tags[]. For analyst-discovered IOCs not in original events.
- `GET /api/v1/cases/stats` — case metrics for dashboard. Returns: open count by severity, MTTD, MTTR, resolution distribution, cases by assignee.

**Source management endpoints:**
- `POST /api/v1/sources` — register a new source. Body: name, type, protocol, port, parser, expected_hosts. Generates API key. Returns source config + key.
- `GET /api/v1/sources` — list all configured sources with current health status (last event, EPS, error count).
- `GET /api/v1/sources/{id}` — source detail. Full config, health history, error log, associated API key (masked).
- `PUT /api/v1/sources/{id}` — update source config. Body: name, expected_hosts, parser. Cannot change type after creation.
- `DELETE /api/v1/sources/{id}` — decommission source. Revokes API key. Marks source as decommissioned. Historical data preserved.
- `POST /api/v1/sources/{id}/test-parser` — test sub-parser against sample log line. Body: raw_log (string). Returns parsed ECS fields or parse error.
- `GET /api/v1/sources/{id}/snippet` — generate configuration snippet. Query param: format (toml/yaml/conf). Returns the copy-paste config for the source device.

**NDR host score endpoints:**
- `GET /api/v1/host-scores` — list hosts with current NDR threat/certainty scores. Query params: quadrant, min_threat, min_certainty, sort_by. Paginated. Returns latest score per host from `akeso-ndr-host-scores` index.
- `GET /api/v1/host-scores/{ip}` — host score detail. Returns: current threat/certainty/quadrant, score history (last 24h trend), active NDR detections, MITRE tactics observed, protocol breakdown for that host.

**Global search endpoint:**
- `GET /api/v1/search` — universal entity search. Query params: `q` (search term), `type` (auto|ip|hash|username|domain|community_id|freetext, default: auto), `limit` (per-group result limit, default: 5). Auto-detects input type and executes parallel `_msearch` across events, alerts, cases, host-scores, and rules indices. Returns grouped results with counts and source-type breakdowns. Respects the global time range for events and alerts; cases and host scores are not time-filtered.

### 6.3 Web Dashboard

React SPA with seven pages: Overview (KPI dashboard), Alerts (triage queue), Cases (incident management), Hunt (query + results), Rules (Sigma management + ATT&CK coverage), Sources (health + onboarding), Settings (user profile + password + MFA + integrations). All routes protected by JWT auth guard. An AI investigation assistant panel is accessible from any page via a persistent header icon. NDR host threat scores are surfaced as risk indicators alongside alerts and cases. See Section 10 for full dashboard design specification and Section 11 for AI assistant specification.

## 7. Build & Development Environment

- **Language:** Go 1.22+
- **Dependencies:** `go-elasticsearch`, `gopkg.in/yaml.v3`, `chi` (HTTP routing), `zap` (logging)
- **Elasticsearch:** 8.x via Docker
- **Dashboard:** React with Tailwind CSS, TanStack Table, Recharts, Nivo, CodeMirror 6, Zustand, TanStack Query, Anthropic API (for AI assistant)

## 8. Risks & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| ES bottleneck | Medium | Bulk indexing, daily rotation, ILM cleanup |
| Sigma parsing edge cases | Medium | SigmaHQ test suite validation |
| Syslog parsing fragility | Medium | Configurable regex parsers, tested for common formats |
| ECS mapping gaps | Low | Start with core fields, preserve unmapped in `labels.*` |
| React dashboard complexity | Medium | Component isolation, TanStack Query for data fetching, Zustand for minimal client state |
| AI assistant hallucination | Medium | Tool-use architecture constrains agent to real API data; no autonomous actions; analyst reviews all output before action |
| NDR event volume | Medium | NDR generates high event volumes (every network session = an event). Mitigated by: NDR batches before shipping, SIEM bulk indexing, ILM with 30-day retention for `ndr:session` events, and optional config flag to filter to detections + protocol metadata only (skip raw sessions). |
| NDR dual logsource matching | Low | NDR protocol events matching both `product: akeso_ndr` and `category: dns/web/tls` could cause unexpected rule matches. Mitigated by explicit logsource mapping tests in Phase 1b and documentation in rule authoring guide. |

## 9. References

- Miller et al. *SIEM Implementation*. McGraw-Hill, 2011.
- Elastic Common Schema: elastic.co/docs/reference/ecs
- SigmaHQ: github.com/SigmaHQ/sigma
- Sigma specification: sigmahq.io/docs/basics/rules.html
- NATO CCDCOE: "IDS for logs: Towards implementing a streaming Sigma rule engine" (Go reference)
- Naglieri, Jack. *Detection at Scale*: detectionatscale.com
- Wazuh analysisd: github.com/wazuh/wazuh
- Elastic Detection Rules: github.com/elastic/detection-rules
- Community ID Flow Hashing: github.com/corelight/community-id-spec — Deterministic flow identifier for cross-tool correlation.
- AkesoNDR Requirements Document v1.0 — Protocol metadata schema, ECS mappings, detection definitions, host scoring model.

---

## 10. Dashboard Design Specification

### 10.1 Navigation Structure

The dashboard uses a collapsible left sidebar (`bg-slate-800`, `indigo-500` active states) with seven top-level sections:

1. **Overview** — Landing dashboard with KPI cards and summary visualizations
2. **Alerts** — Alert triage queue with flyout detail panels
3. **Cases** — Incident management with case queue, flyout, and timeline
4. **Hunt** — Query interface with autocomplete, results table, pivot actions
5. **Rules** — Sigma rule management grouped by MITRE ATT&CK tactic
6. **Sources** — Data source health monitoring and onboarding wizard
7. **Settings** — User profile (display name, password change, MFA enrollment), integrations, theme configuration

The sidebar is 264px wide (`w-64`) on desktop with a collapse toggle to icon-only mode (`w-16`). On mobile, it renders as a full-width overlay with `bg-black/50` backdrop. Active pages are highlighted with `bg-indigo-500/10 text-indigo-400 border-l-2 border-indigo-500`.

The global header bar is sticky (`sticky top-0 z-30`) with `backdrop-blur` and contains: global time range picker (left), global search input with universal entity search and command palette (center), AI assistant toggle button (right), notification dropdown (right), and authenticated user avatar dropdown with profile link and sign out (far right).

#### 10.1.1 Global Time Range Picker

The time range picker button (left side of header) controls the time window for all dashboard data: Overview KPI cards and charts, Alert triage queue, Hunt page queries, source health sparklines, and global search results. The selected time range is stored in the Zustand global store and consumed by every TanStack Query hook across all pages.

**Quick-select presets:** Clicking the button opens a Headless UI `<Popover>` dropdown with preset buttons: Last 15m, 1h, 4h, 24h, 7d, 30d. The button label updates to reflect the current selection (e.g., "Last 24 hours"). Default: 24h.

**Absolute range:** A "Custom range" option at the bottom of the dropdown opens a `react-day-picker` calendar with start/end date+time inputs for precise historical investigation.

**Auto-refresh toggle:** Below the presets, a row of auto-refresh options: Off (default), 10s, 30s, 1m, 5m. When active, a subtle animated indicator appears on the button. Controls the polling interval for Overview charts, Alert SSE feed, and Source health data.

**Hunt page override:** The Hunt page's inline time picker (Section 10.5) uses the same `TimePicker.jsx` component. When the analyst changes the time range from the Hunt page, it updates the global state. When they navigate away and back, the global time range persists. This ensures the header button and the Hunt page picker always show the same value.

**State propagation:** Changing the time range triggers a re-fetch of all visible TanStack Query hooks via query invalidation. Charts, tables, KPI cards, and search results all update to reflect the new window. Date math is handled by `date-fns`.

#### 10.1.2 Global Search

The global search input (center of header) provides two modes: **entity search** (default) and **command palette** (activated by typing `/` as the first character, or pressing `Cmd+Shift+P` / `Ctrl+Shift+P` from anywhere).

**Entity search — type detection.** The search bar auto-detects the input type on every keystroke (debounced 200ms) and targets the correct ECS fields. A small badge appears inline showing the detected type (e.g., "IP", "SHA-256", "User") so the analyst knows what will be searched before pressing Enter.

| Input Pattern | Detected Type | Fields Searched |
|---------------|---------------|-----------------|
| IPv4 or IPv6 | IP address | `source.ip`, `destination.ip`, `host.ip` |
| 64 hex chars | SHA-256 hash | `file.hash.sha256` |
| 40 hex chars | SHA-1 hash | `file.hash.sha1` |
| 32 hex chars | MD5 hash / JA3 | `file.hash.md5`, `tls.client.ja3`, `tls.client.ja4` |
| Starts with `1:` | Community ID | `network.community_id` |
| FQDN pattern (dots, no spaces) | Domain/hostname | `dns.question.name`, `host.name`, `tls.client.server_name`, `url.domain` |
| Windows path (`C:\...`) | File path | `file.path`, `process.executable` |
| Prefixed with `CASE-` or `ALERT-` | ID lookup | `case.id`, `alert.id` |
| Short alphanumeric, no dots | Username | `user.name` |
| Anything else | Free text | Full-text across `event.action`, `process.command_line`, `rule.name`, `case.title`, `ndr.detection.name` |

**Entity search — grouped results.** Results appear in a dropdown panel (full header width, max 480px tall, scrollable) grouped by category in priority order: NDR Host Score (IP searches only, shows threat/certainty/quadrant) → Alerts (compact rows: severity badge, rule name, timestamp, up to 5 shown) → Cases (severity badge, title, status) → Events (count + source-type breakdown as colored badges, not full documents) → Rules (matching by name/description). Groups with zero results are hidden. Click any result to navigate: Events → Hunt page with pre-built query, Alerts → Alerts page with flyout open, Cases → Cases page with flyout open, Host Score → host score detail view, Rules → Rules page with rule highlighted.

**Command palette.** Typing `/` or pressing `Cmd+Shift+P` / `Ctrl+Shift+P` switches to command mode. Placeholder changes to "Type a command..." and the dropdown shows fuzzy-matched navigation commands (`/alerts`, `/cases`, `/hunt`, `/rules`, `/sources`, `/settings`, `/overview`) and quick actions (`/add source`, `/reload rules`, `/dark`, `/light`, `/ai`, `/logout`). Enter executes the highlighted command.

**Recent searches.** When focused with empty input, the dropdown shows the last 10 searches (localStorage, keyed to authenticated user) with detected type badges and result count summaries. Individual entries clearable via "×"; "Clear all" at bottom.

**Keyboard shortcuts:**

| Shortcut | Action |
|----------|--------|
| `Cmd+Shift+P` / `Ctrl+Shift+P` | Focus search bar in command palette mode |
| `Cmd+/` / `Ctrl+/` | Focus search bar in entity search mode |
| `Escape` | Close dropdown, blur search bar |
| `↑` / `↓` | Navigate results in dropdown |
| `Enter` | Execute selected result / command |

### 10.2 Overview Dashboard

The landing page follows the 3-30-300 rule: KPIs scannable in 3 seconds, filtering context in 30 seconds, detail-on-demand in 300 seconds.

**Row 1 — KPI Cards (5 cards in responsive grid):** Each card shows metric label, large formatted value (`Intl.NumberFormat` with `notation: 'compact'`), Recharts sparkline (7-day trend), and percentage-change indicator. The five KPIs: Events/sec, Open Alerts (with severity breakdown dots), MTTD, MTTR, Source Health (active/expected gauge).

**Row 2 — Alert Trend + Distribution (2-column):** Left: stacked area chart (Recharts) showing alerts by severity over 24 hours. Right: horizontal bar chart of top 10 triggered rules ranked by alert count, color-coded by highest severity.

**Row 3 — ATT&CK Coverage + Source Health (2-column):** Left: compact MITRE ATT&CK heatmap (Nivo `<ResponsiveHeatMap>`) with blue sequential color scale. Right: source health table with status dot, name, current EPS, inline sparkline, last-event timestamp.

**Row 4 — NDR Host Risk Panel (full-width):** Condensed host threat matrix showing hosts in Critical and High quadrants only. Each host row shows: IP, hostname, threat score, certainty score, quadrant badge, active detection count, top MITRE tactic, last detection timestamp. Clickable rows drill into host score detail (score history chart, detection list, protocol breakdown). Panel header shows total monitored hosts and count per quadrant. Collapsed by default if no Critical/High hosts. Data sourced from `GET /api/v1/host-scores?quadrant=critical,high`.

### 10.3 Alert Triage Queue

**Table columns** (customizable via column picker):

| Column | Width | Renderer |
|--------|-------|----------|
| Checkbox | 40px | Bulk selection |
| Severity | 80px | Color-coded pill badge |
| Timestamp | 140px | Relative format with absolute tooltip |
| Rule Name | 200px+ | Truncated with tooltip, clickable |
| Source IP | 130px | Monospace, right-click context menu |
| Destination IP | 130px | Monospace, right-click context menu |
| User | 120px | Entity link with risk indicator |
| MITRE Tactic | 120px | Badge with tactic abbreviation |
| Status | 100px | Workflow state badge |
| Assignee | 100px | Avatar + name or "Unassigned" |

**Filters:** Four dropdowns (Status, Severity, Rule, MITRE Tactic) plus KQL-style search bar above the table.

**Severity indicators:** 3px colored left border on each row (Critical=red-500, High=orange-500, Medium=yellow-500, Low=blue-500) for instant visual scanning.

**Flyout detail panel:** Right-side drawer (400–500px wide) with three tabs: Overview (rule description, MITRE mapping, entity enrichment, related alerts count, NDR host score badge if available for involved hosts), Evidence (field-value pairs with inline filter/exclude actions, JSON toggle), Timeline (related events for same entity ±1 hour).

**Flyout footer actions:** Acknowledge (primary), Escalate to Case (secondary), Close (with disposition dropdown: False Positive, True Positive, Benign), Assign dropdown.

**Bulk actions:** Floating bar on checkbox selection: "X alerts selected" with Acknowledge, Close, Assign, Escalate, Add Tags.

**Alert status workflow:** New → Acknowledged → In Progress → Escalated → Closed (with required disposition).

**Real-time updates:** Server-Sent Events (SSE) for alert feed. Buffer new alerts while analyst is reading; show dismissible banner "14 new alerts — Click to load." Never reorder rows or close flyout during background refresh. Preserve checkbox selection across refreshes.

**Alert fatigue mitigation:** Alert grouping by rule name, source IP, or user with up to 3 nesting levels. Each group row shows severity distribution, total count, most recent timestamp.

### 10.4 Cases Page

**Case queue table:** Columns for severity, title, status badge, assignee, alert count, observable count, MITRE tags, created timestamp, last updated. Filterable by status, severity, assignee. Sortable by any column.

**Case detail flyout:** Right-side drawer (consistent with alert flyout) with four tabs:
- **Overview** — Title, severity, status, assignee, tags, MITRE mapping
- **Alerts** — Linked alerts table with expandable event detail
- **Observables** — Grouped by type with pivot actions (same context menu as Hunt page)
- **Timeline** — Chronological log of all analyst activity, comments, status changes, alert merges

**Case actions:** Assign, change status, add comment, add observable, merge alerts, close with resolution. All actions logged to timeline.

**KPI integration:** Case metrics feed the Overview dashboard's MTTD and MTTR cards. Closed cases with `resolution_type = true_positive` contribute to detection efficacy metrics.

### 10.5 Threat Hunting Query Interface

**Query bar:** Built with CodeMirror 6 (`@uiw/react-codemirror` wrapper). Custom Lezer grammar for AkesoSIEM's query language. Three-stage contextual autocomplete via `@codemirror/autocomplete`: field names → operators (type-aware) → values (fetched from index). Real-time validation via `@codemirror/lint`. Syntax highlighting: commands in blue, field names in purple/teal, operators in orange, string values in green, numbers in cyan, pipes in bold gray.

**Time picker:** Custom component using Headless UI `<Popover>` with quick-select buttons (15m, 1h, 4h, 24h, 7d, 30d) and absolute range picker (`react-day-picker` + time inputs). Auto-refresh toggle (Off, 10s, 30s, 1m, 5m). Date math via `date-fns`.

**Results histogram:** Time-bucketed bar chart (Recharts) with brush-to-zoom — click-and-drag to select sub-range, updates time picker and re-queries.

**Results table:** TanStack Table v8 with `@tanstack/react-virtual` for row virtualization (100K+ rows). Column picker, expandable rows (Table/JSON/Raw sub-tabs), server-side pagination (25/50/100/200 per page), field statistics sidebar (available fields with top 10 values as mini horizontal bars).

**Pivot actions via context menu:** Right-click any cell value for type-aware actions:
- **IP addresses:** Filter in/out, Search all events, VirusTotal, AbuseIPDB, Shodan, WHOIS, Copy
- **File hashes:** Search across endpoints, VirusTotal, MalwareBazaar, Copy
- **Usernames:** Search all activity, View entity risk, View auth events, Copy
- **Any value:** Filter in (+), Filter out (−), Add to saved query, Copy

External lookups via admin-configurable URL templates.

**Saved queries:** Query Library panel with tabs: Recent (auto-saved last 20), Saved (user-named with tags), Shared (organization-wide). "Promote to Detection Rule" button pre-fills rule creation form.

### 10.6 Rules Page — Detection Rules & ATT&CK Coverage

**Detection Rules list:** TanStack Table with: enabled toggle, rule name, severity badge, MITRE tactic/technique tags, hit count, last triggered, status (stable/test/experimental), data source availability. Grouped by MITRE ATT&CK tactic with collapsible sections.

**ATT&CK Coverage heatmap:** Nivo `<ResponsiveHeatMap>` with 14 tactic columns (Reconnaissance through Impact) and technique rows. Three-tier coverage states: ✅ Detected (active rule + data source), ⚠️ Logged (data source but no rule), ❌ Blind (no data source). Interactive cells open popover with technique description, associated rules, alert count. Compact/expanded toggle. Coverage percentage per tactic. ATT&CK Navigator-compatible JSON layer export.

### 10.7 Sources Page — Health & Onboarding

**KPI cards (top row):** Total EPS, Active Sources (vs. expected gauge), Error Rate (last hour).

**Ingestion rate chart:** Full-width time-series area chart (24h) with anomaly band (mean ± 2σ shaded in light red).

**Source health table:** Status dot (green/yellow/red), source name, type, current EPS, EPS trend sparkline (24h), error count, latency, last event timestamp. Expandable rows with detailed EPS chart, error log, latency histogram, config details. Error rows highlighted with `bg-red-50 dark:bg-red-500/10`.

**Onboarding wizard:** "Add Source" button opens multi-step modal: (1) source type card selector, (2) type-specific config form, (3) configuration snippet with copy button (CodeMirror 6 in read-only mode with syntax highlighting), (4) live verification polling for first event. Step indicator bar at top of modal.

**Sub-parser test interface:** Textarea + parser dropdown + "Test" button → parsed ECS fields or error. Accessible from wizard Step 2 (syslog types) and standalone on Sources page.

### 10.8 Dark Mode & Severity Color System

Default to **dark mode** with three-way toggle (Dark / Light / System) persisted to `localStorage`. Use Tailwind's class strategy (`darkMode: 'class'`).

**Surface color palette:**

| Role | Dark Mode | Light Mode |
|------|-----------|------------|
| Page background | `slate-950` (#020617) | `slate-50` (#f8fafc) |
| Sidebar | `slate-900` (#0f172a) | `slate-800` (#1e293b) — always dark |
| Card surface | `slate-800` (#1e293b) | `white` (#ffffff) |
| Elevated surface | `slate-700` (#334155) | `slate-50` (#f8fafc) |
| Primary text | `slate-50` (#f8fafc) | `slate-900` (#0f172a) |
| Secondary text | `slate-300` (#cbd5e1) | `slate-600` (#475569) |
| Borders | `slate-700` (#334155) | `slate-200` (#e2e8f0) |
| Active/accent | `indigo-500` (#6366f1) | `indigo-500` (#6366f1) |

**Severity color palette (WCAG AA compliant):**

| Severity | Dark Mode Badge | Light Mode Badge | Solid |
|----------|----------------|-----------------|-------|
| Critical | `bg-red-500/20 text-red-400 border-red-500/30` | `bg-red-50 text-red-700 border-red-200` | `bg-red-500` |
| High | `bg-orange-500/20 text-orange-400 border-orange-500/30` | `bg-orange-50 text-orange-700 border-orange-200` | `bg-orange-500` |
| Medium | `bg-yellow-500/20 text-yellow-300 border-yellow-500/30` | `bg-yellow-50 text-yellow-700 border-yellow-200` | `bg-yellow-500` |
| Low | `bg-blue-500/20 text-blue-400 border-blue-500/30` | `bg-blue-50 text-blue-700 border-blue-200` | `bg-blue-500` |
| Info | `bg-slate-500/20 text-slate-300 border-slate-500/30` | `bg-slate-100 text-slate-600 border-slate-200` | `bg-slate-500` |

Note: Yellow text on dark backgrounds requires `text-yellow-300` (#fde047) for 4.5:1 WCAG AA contrast.

**Chart colors:** Dark mode series: `blue-400`, `green-400`, `amber-400`, `red-400`, `purple-400`, `cyan-400`. Light mode series: `-600` variants. Grid lines: `slate-700` (dark) / `slate-200` (light). Apply via `useChartTheme()` hook reading theme from Zustand.

### 10.9 React Library Stack

| Category | Library | Purpose |
|----------|---------|---------|
| Styling | `tailwindcss` v4.x | Utility-first CSS with `dark:` variant |
| UI Primitives | `@headlessui/react` v2.x | Dialog, Menu, Popover, Listbox, Tab, Switch, Disclosure |
| Font | `@fontsource/inter` | Inter at 500 weight default |
| Data Tables | `@tanstack/react-table` v8.x | Alert queue, case queue, rule management, source health (~15KB gzipped) |
| Virtual Scroll | `@tanstack/react-virtual` v3.x | Hunt results table (100K+ rows) |
| Charts | `recharts` v2.x | Time-series, bar charts, sparklines |
| Heatmap | `@nivo/heatmap` + `@nivo/core` | MITRE ATT&CK coverage matrix |
| Query Editor | `@codemirror/view` v6.x + `@codemirror/autocomplete` + `@codemirror/lint` | SIEM query bar (~300KB) |
| CM Wrapper | `@uiw/react-codemirror` v4.x | React wrapper for CodeMirror 6 |
| Date Math | `date-fns` v3.x | Time picker, relative timestamps |
| Calendar | `react-day-picker` v8.x | Absolute range picker |
| Server State | `@tanstack/react-query` v5.x | Data fetching, caching, polling, SSE integration |
| Client State | `zustand` v5.x | Sidebar, filters, time range, theme, assistant conversation (~1KB gzipped) |
| AI Assistant | Anthropic Messages API | Tool-use with streaming for investigation assistant (React-side, no backend dependency) |
| E2E Testing | `@playwright/test` | Headless browser testing for all dashboard workflows (auth, triage, hunting, cases, sources, rules) |

---

## 11. AI Investigation Assistant Specification

### 11.1 Architecture

The AI assistant is a React-side chat panel that calls the Anthropic API with tool definitions mapped to the SIEM's existing REST API. The agent doesn't touch the Go backend's hot path — it's a consumer of the same API the dashboard uses. Anything the dashboard can display, the agent can query, summarize, and reason about.

```
akeso-dashboard (React)
├── [All dashboard pages]
├── AI Assistant Panel ──→ Anthropic API (tool_use)
│                          Tools = SIEM REST API endpoints
└── SIEM REST API Client ──→ akeso-query (Go) ──→ Elasticsearch
```

### 11.2 Tool Definitions

The agent's tools are the SIEM's existing REST API endpoints wrapped as Anthropic tool schemas:

| Tool Name | Maps To | Description |
|-----------|---------|-------------|
| `search_events` | `POST /api/v1/query` | Execute a SIEM query from natural language |
| `list_alerts` | `GET /api/v1/alerts` | List alerts with filters |
| `get_alert` | `GET /api/v1/alerts/{id}` | Full alert detail with linked events and MITRE mapping |
| `get_case` | `GET /api/v1/cases/{id}` | Case detail with observables, timeline, linked alerts |
| `list_cases` | `GET /api/v1/cases` | List cases with filters |
| `get_case_stats` | `GET /api/v1/cases/stats` | Case metrics (open count, MTTD, MTTR) |
| `get_rule` | `GET /api/v1/rules/{id}` | Sigma rule definition with detection logic |
| `list_rules` | `GET /api/v1/rules` | Loaded Sigma rules with hit counts |
| `get_source_health` | `GET /api/v1/sources` | Ingestion source health |
| `lookup_observable` | `GET /api/v1/search` | Search all indices for a specific IP, hash, username, domain, or Community ID via universal entity search |
| `get_mitre_technique` | Static lookup | MITRE ATT&CK technique description and linked rules |
| `get_host_scores` | `GET /api/v1/host-scores` | NDR host threat/certainty scores, filterable by quadrant |
| `get_host_score_detail` | `GET /api/v1/host-scores/{ip}` | NDR host score detail: history, active detections, MITRE tactics |

### 11.3 Capabilities

**Query Assistance:** Natural language → SIEM query syntax translation. The agent generates valid queries, validates against the grammar, and offers "Copy to Hunt" actions. Also works in reverse — paste a query, agent explains it in plain language.

**Alert Triage Summary:** Multi-step tool use to summarize an alert: what fired, why, process parent chain, cross-source context (AV/DLP/NDR events for same host/user), NDR host score risk assessment, and recommended actions. For alerts involving network-layer detections, the agent queries NDR host scores and active NDR detections to enrich the triage narrative.

**Investigation Copilot:** From the Cases page, the agent runs a multi-step investigation: scope (hosts/users) → timeline → lateral movement check (including NDR lateral movement detections) → data exposure check (DLP events + NDR exfiltration detections) → observable enrichment → NDR host score assessment → structured narrative with recommendations. Each step streams to the analyst in real time. Analyst can interrupt and redirect.

**Detection Rule Drafting:** Generates Sigma YAML from natural language pattern descriptions with correct logsource mapping, field names, modifiers, and MITRE ATT&CK tags. Optionally tests against historical data to estimate hit rate and false positive rate.

**Cross-Portfolio Attack Narrative:** When cross-source correlation rules fire, the agent constructs a unified incident story from EDR, AV, DLP, and NDR telemetry — attributing each stage of the kill chain to the correct product with timestamps, entities, and recommended response actions. For NDR-involved narratives, the agent includes network session metadata (Community IDs, JA3 fingerprints, connection states), NDR behavioral detection details (beacon intervals, exfiltration volumes, lateral movement fan-out), and host threat score progression.

### 11.4 UI Design

The assistant is a **slide-out right panel** (400px wide) accessible via a persistent icon button in the global header bar. It opens alongside any page.

**Panel layout:** Header with context indicator, message stream with markdown rendering and collapsible tool call cards, input bar with multi-line support, and context-dependent quick action buttons ("Explain this alert", "Summarize investigation", "Write a Sigma rule for this query").

**Streaming:** Token-by-token via Anthropic streaming API. Tool calls appear as in-progress indicators that resolve to collapsible result cards.

**"Copy to..." actions:** Copy query to Hunt (injects into query bar), Copy to Case Comment (posts to case timeline attributed to "AkesoAI"), Copy Sigma Rule (modal with syntax highlighting + save), Copy to Clipboard.

### 11.5 Design Constraints

- **No direct ES access.** Agent only uses the REST API — same endpoints as the dashboard. Cannot bypass access controls.
- **No autonomous actions.** Agent never modifies state without analyst confirmation. Copilot, not autopilot.
- **Ephemeral conversations.** Zustand in-memory only. No server-side persistence. Cleared on page reload.
- **Graceful degradation.** If Anthropic API is unavailable, assistant shows offline indicator. Dashboard functions identically.
- **Token budget awareness.** Tool results truncated to configurable limit (default 4000 tokens) with "results truncated" indicator.

### 11.6 System Prompt

Stored as `web/src/agent/system_prompt.md`, loaded at runtime. Covers: Akeso portfolio context (including AkesoNDR capabilities, protocol metadata fields, host scoring model, and behavioral detection types), ECS field reference (including all `ndr.*` extension fields), query syntax grammar, Sigma rule structure, MITRE ATT&CK context, Community ID cross-source correlation patterns, and investigation methodology.

---

# PART II: IMPLEMENTATION PHASES

## 12. How To Use Part II With Claude Code

Same workflow as AkesoEDR: each task has an ID, files, acceptance criteria, and complexity (S/M/L/XL).

---

### Phase 0: Project Scaffolding

**Goal:** Monorepo, Go module, ES Docker setup, shared types, config, test fixtures.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P0-T1 | Init Go module, dirs, Makefile (build/test/run). | `go.mod`, `Makefile`, all `cmd/` + `internal/` dirs | `make build` compiles all binaries. | S |
| P0-T2 | Docker Compose for ES 8.x + Kibana. Health check wait. | `docker-compose.yml`, `scripts/wait-for-es.sh` | `docker-compose up` → ES healthy at :9200. | S |
| P0-T3 | Core ECS event Go struct. All field groups from 3.3 including `ndr.*`, `dns.*`, `http.*`, `tls.*`, `smb.*`, `kerberos.*`, `ssh.*` extension fields. JSON tags. Original raw field. | `internal/common/ecs_event.go` | Compiles. Round-trip marshal/unmarshal. All field groups covered. | M |
| P0-T4 | Config loading (TOML): ES, ingest, correlate, query, case management sections. | `internal/config/config.go`, `akeso.toml` | Loads and validates. Missing fields → clear errors. | M |
| P0-T5 | ES client wrapper: connect, health, index template (ECS mappings), bulk index, search. | `internal/store/es_client.go`, `index_template.go` | Connects. Template created. Bulk index 100 events, search returns them. | L |
| P0-T6 | Static test fixture files for all 6 source types (AkesoEDR, AkesoAV, AkesoDLP, AkesoNDR, Windows Events, syslog). Cover every event type from Appendix A including all 15 NDR event types. Include edge cases (missing fields, malformed JSON, unicode paths, oversized payloads, duplicate event_ids). ~600 events total. | `tests/fixtures/**/*.ndjson`, `tests/fixtures/**/*.xml`, `tests/fixtures/**/*.txt`, `tests/fixtures/edge_cases/` | Every event type has ≥3 fixture events. All conform to Appendix A schemas. NDR fixtures include session, dns, http, tls, smb, kerberos, ssh, detection, signature, host_score event types. Edge case files present. Replayable via `akeso-cli ingest replay`. | M |

---

### Phase 1: HTTP Ingestion & AkesoEDR Parser

**Goal:** Accept JSON over HTTP, normalize AkesoEDR telemetry to ECS.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P1-T1 | HTTP listener. POST `/api/v1/ingest`. API key auth. NDJSON support. Rate limiting. | `internal/ingest/http_listener.go`, `cmd/akeso-ingest/main.go` | Valid key → 202. Invalid → 401. 100-event NDJSON accepted. | M |
| P1-T2 | Normalization engine framework. Source type routing. Parser registry. | `internal/normalize/engine.go`, `parser_registry.go` | Routes to correct parser. Unknown type → raw preserved. | M |
| P1-T3 | AkesoEDR parser. Map all `AKESO_EVENT` types to ECS. | `internal/normalize/parsers/akeso_edr.go` | Each event type normalizes correctly. Round-trip tests. | L |
| P1-T4 | End-to-end pipeline: ingest → normalize → ES. Verify searchable. | `internal/ingest/pipeline.go` | POST 100 events → all in ES within 5s with correct ECS fields. | M |
| P1-T5 | Scenario generator CLI (Python). YAML scenario parser with timeline definitions, entity directory (hosts, users, network topology), noise profile mixer (workstation, server, DC, firewall, NDR sensor), NDJSON output. Ship 3 initial scenarios: credential_theft, lateral_movement, malware_delivery. Each scenario produces events across multiple source types with realistic timing and causal relationships, mixed with background noise at ~95/5 ratio. | `tools/generate_scenarios.py`, `tools/scenarios/*.yaml`, `tools/profiles/*.yaml`, `tools/entities/*.yaml` | `python generate_scenarios.py --scenario credential_theft --output out.ndjson` produces valid NDJSON. Events conform to Appendix A schemas for all source types used. Timestamps are realistic with proper causal ordering. Entity relationships consistent across sources (same hostnames, IPs, usernames). Background noise mixed in. | L |

---

### Phase 1a: AkesoAV & DLP Parsers

**Goal:** Normalize Akeso AV and Akeso DLP telemetry to ECS, enabling cross-portfolio correlation.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P1a-T1 | Akeso AV parser. Map all AV event types to ECS: `av:scan_result` → `event.category: malware` + `file.*` + `av.*`, `av:quarantine` → `event.action: quarantine`, `av:realtime_block` → `event.type: denied` + `process.*`. | `internal/normalize/parsers/akeso_av.go` | Each AV event type normalizes correctly. `av.scan.result`, `av.signature.name`, `file.hash.*` all populated. Round-trip tests. | M |
| P1a-T2 | Akeso DLP parser. Map all DLP event types to ECS: `dlp:policy_violation` → `event.category: file` + `dlp.*`, `dlp:block` → `event.outcome: failure`, `dlp:removable_media` → `event.type: creation` + device info. | `internal/normalize/parsers/akeso_dlp.go` | Each DLP event type normalizes correctly. `dlp.policy.name`, `dlp.classification`, `dlp.channel` all populated. Round-trip tests. | M |
| P1a-T3 | Logsource mapping for AV and DLP. Register `product: akeso_av` and `product: akeso_dlp` in logsource map so Sigma rules can target these event types specifically. | `parsers/logsource_map.yaml` (extend) | Sigma rule with `product: akeso_av` only evaluates AV events. Same for DLP. Cross-product rules with `category: malware` match both AV scan results and EDR malware detections. | S |
| P1a-T4 | Cross-portfolio detection rules. Write 5 Sigma rules that correlate across EDR+AV, EDR+DLP, and AV+DLP as described in Section 5.3. | `rules/akeso_portfolio/` (5 `.yml` files) | Rules parse and load. Manually verified against test event scenarios. | M |

---

### Phase 1b: AkesoNDR Parser

**Goal:** Normalize AkesoNDR telemetry to ECS, register logsource mappings, enable cross-portfolio network correlation.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P1b-T1 | AkesoNDR parser. Validate and enrich pre-normalized NDR events: add `event.ingested` timestamp, validate ECS field presence for all 15 `ndr:*` event types (`ndr:session`, `ndr:dns`, `ndr:http`, `ndr:tls`, `ndr:smb`, `ndr:kerberos`, `ndr:ssh`, `ndr:smtp`, `ndr:rdp`, `ndr:ntlm`, `ndr:ldap`, `ndr:dcerpc`, `ndr:detection`, `ndr:signature`, `ndr:host_score`). Ensure `ndr.*` custom extension fields are preserved and indexed. | `internal/normalize/parsers/akeso_ndr.go` | Each NDR event type passes validation. `event.ingested` added. `ndr.detection.name`, `ndr.host_score.threat`, `ndr.session.community_id` all correctly preserved. Missing required ECS fields → logged warning + raw preserved. Round-trip tests for all 15 event types. | L |
| P1b-T2 | NDR host score upsert logic. Route `ndr:host_score` events to both the standard time-series index AND the dedicated `akeso-ndr-host-scores` index with upsert-by-host-IP semantics (latest score wins). | `internal/normalize/parsers/akeso_ndr_host_score.go`, `internal/store/host_score_index.go` | Host score event indexed in both locations. Second score for same host IP updates (not duplicates) the dedicated index. Dashboard query returns latest score per host. | M |
| P1b-T3 | Logsource mapping for NDR. Register `product: akeso_ndr` in logsource map. Implement **dual logsource matching**: `ndr:dns` events match both `product: akeso_ndr` AND `category: dns`, `ndr:http` matches `category: web`, `ndr:tls` matches `category: tls`, `ndr:smb` matches `category: smb`, `ndr:kerberos` matches `category: kerberos`. Test that community SigmaHQ network rules evaluate correctly against NDR events. | `parsers/logsource_map.yaml` (extend), `internal/correlate/logsource_mapping.go` (extend) | Sigma rule with `product: akeso_ndr` only evaluates NDR events. Sigma rule with `category: dns` evaluates BOTH NDR DNS events and syslog DNS events. SigmaHQ rule targeting `dns.question.name contains "malicious"` fires on NDR DNS metadata. No false logsource routing. | M |
| P1b-T4 | Community ID cross-source linking. Index `network.community_id` as a keyword field on all NDR events. Verify that queries on `network.community_id` return NDR session metadata and any EDR/FW events with the same community_id, enabling cross-source pivot on the same network flow. | `internal/normalize/parsers/community_id.go` (shared utility) | Query `network.community_id = "1:abc..."` returns NDR session + any EDR/FW events with same community_id. Cross-source pivot works in query API. | S |
| P1b-T5 | NDR cross-portfolio Sigma rules. Write 5 Sigma correlation rules from Section 5.3: (1) EDR credential theft → NDR lateral movement, (2) NDR beacon → EDR process ID, (3) NDR SMB transfer → AV malware detection, (4) NDR exfiltration → DLP confidential classification, (5) Full chain: NDR recon → EDR cred dump → NDR lateral → NDR exfil. | `rules/akeso_portfolio/ndr_cross_*.yml` (5 `.yml` files) | Rules parse and load as valid Sigma 2.0 temporal correlation rules. Logsource `product: akeso_ndr` targets correctly. Manually verified against test event scenarios. | L |

---

### Phase 2: Windows Event Log Ingestion

**Goal:** Ingest and normalize Windows Event Logs.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P2-T1 | Windows Event XML parser. Extract EventID, Channel, Computer, EventData. | `internal/normalize/parsers/winevt_xml.go` | Parse 4624 XML. All fields correct. Missing fields handled. | M |
| P2-T2 | Winlogbeat JSON parser. Map `winlog.*` → ECS. | `internal/normalize/parsers/winevt_json.go` | Parse 4688 JSON. `winlog.event_data.NewProcessName` → `process.executable`. | M |
| P2-T3 | ECS mappers for key Event IDs: 4624/4625, 4688, 4768/4769, 7045, Sysmon 1/3/11. | `internal/normalize/parsers/winevt_ecs_mappers.go` | Correct ECS mapping per event ID. Sigma Windows rules target correctly. | L |
| P2-T4 | WEF HTTP collector endpoint `/api/v1/ingest/wef`. | `internal/ingest/wef_collector.go` | 50 mixed Windows events → all in ES normalized. | M |

---

### Phase 3: Syslog Ingestion

**Goal:** Accept syslog from network devices and Linux hosts.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P3-T1 | Syslog TCP/UDP listener. RFC 5424 + 3164. | `internal/ingest/syslog_listener.go`, `parsers/syslog.go` | Both formats parsed via netcat. TCP + UDP both work. | M |
| P3-T2 | Syslog TLS listener. Self-signed cert script. | `internal/ingest/syslog_tls.go`, `scripts/gen-certs.sh` | TLS syslog received. Non-TLS rejected. | M |
| P3-T3 | Configurable syslog sub-parsers (YAML regex). Ship: iptables, auditd, generic KV. | `internal/normalize/parsers/syslog_subparsers.go`, `parsers/*.yaml` | iptables → network ECS. auditd → process ECS. Unknown → raw preserved. | L |
| P3-T4 | Syslog → ECS normalization. Integrate into pipeline. | `internal/normalize/parsers/syslog_ecs.go` | All syslog types in ES with correct ECS. Sigma `product: linux` targets correctly. | M |

---

### Phase 4: Sigma Single-Event Rules

**Goal:** Sigma rule parser + single-event evaluation engine.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P4-T1 | Sigma YAML parser. Load rules into Go structs. Multi-doc handling. | `internal/correlate/sigma_parser.go`, `sigma_types.go` | 50 SigmaHQ rules parse without error. | L |
| P4-T2 | Detection evaluator. Selection matching + modifiers + condition parser (AND/OR/NOT). | `internal/correlate/sigma_evaluator.go`, `sigma_modifiers.go` | `contains`, `re`, `all`, `cidr`, boolean conditions all evaluate correctly. | XL |
| P4-T3 | Logsource routing. Map Sigma logsource → ECS filters. Configurable mapping table. | `internal/correlate/logsource_mapping.go`, `parsers/logsource_map.yaml` | `product: windows, service: sysmon` only evaluates Sysmon events. | M |
| P4-T4 | Real-time evaluation pipeline. Fan-out: events → store + correlate. Alert on match. | `internal/correlate/pipeline.go`, `cmd/akeso-correlate/main.go` | Matching event → alert in ES within 2s. Non-matching → no alert. | L |
| P4-T5 | Hot-reload. File watcher + CLI trigger. Atomic swap. No event loss. | `internal/correlate/rule_loader.go` | New rule file → active in 10s. Removed → stops firing. | M |

---

### Phase 5: Sigma Correlation Rules

**Goal:** Multi-event correlation: thresholds, distinct counts, temporal sequences.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P5-T1 | Correlation rule parser. `event_count`, `value_count`, `temporal` types. | `internal/correlate/sigma_correlation_parser.go` | All three types parse. Invalid → clear error. | M |
| P5-T2 | Event count correlation. In-memory counters per group-by key. Threshold + window. | `internal/correlate/correlation_event_count.go` | >5 failed logons / user / 10min → alert. 4 → no alert. | L |
| P5-T3 | Value count correlation. Distinct values per group-by key. | `internal/correlate/correlation_value_count.go` | >10 distinct hosts / user / 1hr → alert. 9 → no alert. | M |
| P5-T4 | Temporal correlation. Ordered multi-rule sequence with shared field. State machine. | `internal/correlate/correlation_temporal.go` | failed→success→lsass in order within 15min → alert. Out of order → no alert. | XL |
| P5-T5 | State management. Expiration goroutine. Memory bounds. Metrics. | `internal/correlate/correlation_state.go` | State expires. Memory stable. Health endpoint shows counts. | M |

---

### Phase 6: Query Engine & REST API

**Goal:** Query language, ES translation, REST API.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P6-T1 | Query parser. Simplified syntax → AST. | `internal/query/parser.go`, `ast.go` | Complex queries parse. Invalid → descriptive error. | L |
| P6-T2 | ES DSL translator. AST → Elasticsearch query JSON. | `internal/query/es_translator.go` | Results match equivalent Kibana query. | L |
| P6-T3 | REST API server. All core endpoints from 6.2. JSON. CORS. Pagination. | `internal/query/api_handlers.go`, `cmd/akeso-query/main.go` | All endpoints return correct JSON. | M |
| P6-T4 | API key management. Create/revoke/list. ES-stored. | `internal/common/auth.go` | Create → ingest works. Revoke → 401. | M |

---

### Phase 7: Web Dashboard

**Goal:** React dashboard for alert triage, case management, hunting, source management, rule visualization, and user authentication with MFA.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P7-T1 | Dashboard shell. React + Tailwind + React Router. Layout: collapsible sidebar, sticky header, content area. Pages: Overview, Alerts, Cases, Hunt, Rules, Sources, Settings. Dark/light mode toggle via Zustand + `darkMode: 'class'`. | `web/src/App.jsx`, `web/src/layouts/`, `web/src/components/Sidebar.jsx`, `web/src/components/Header.jsx`, `web/src/stores/themeStore.js` | Loads. Nav works. Responsive. Dark/light toggle persists. Sidebar collapses. | M |
| P7-T2 | Alert queue page. TanStack Table with columns from 10.3. Severity left-border accent. Filter dropdowns. Flyout detail panel (3 tabs). Bulk actions bar. SSE integration for real-time updates with buffered banner. | `web/src/pages/Alerts.jsx`, `web/src/components/AlertFlyout.jsx`, `web/src/components/SeverityBadge.jsx` | Alerts display. Sort. Filter. Expand flyout. Acknowledge. Bulk select. SSE banner shows new alert count. | L |
| P7-T3 | Event search page. CodeMirror 6 query bar with custom Lezer grammar, autocomplete, lint. Time picker (relative + absolute). Results histogram with brush-to-zoom. TanStack Table with virtual scroll, expandable rows (Table/JSON/Raw), column picker. Field statistics sidebar. Context menu pivot actions. | `web/src/pages/Hunt.jsx`, `web/src/components/QueryBar.jsx`, `web/src/components/TimePicker.jsx`, `web/src/components/ResultsTable.jsx`, `web/src/components/ContextMenu.jsx` | Query → results. Autocomplete suggests fields. Time range works. Brush-to-zoom updates time picker. Expandable rows show all formats. Right-click opens pivot menu. | XL |
| P7-T4 | Overview dashboard. 5 KPI cards with sparklines. Alert trend stacked area chart. Top 10 rules bar chart. ATT&CK coverage mini-heatmap. Source health summary table. NDR Host Risk Panel (Row 4). All fed by TanStack Query with polling. | `web/src/pages/Overview.jsx`, `web/src/components/KPICard.jsx`, `web/src/components/AlertTrendChart.jsx`, `web/src/components/TopRulesChart.jsx`, `web/src/components/NDRHostRiskPanel.jsx` | Correct metrics. Sparklines render. Charts display. NDR panel shows Critical/High hosts. Updates on refresh interval. | L |
| P7-T5 | Source configuration data model and ES index. Go structs for source config (name, type, protocol, port, parser, expected_hosts, api_key_id, status). Index template. CRUD service with API key generation integration. | `internal/sources/types.go`, `internal/sources/service.go`, `internal/store/source_template.go` | Structs compile. Create source → API key generated → source retrievable. Delete → key revoked. Template applied in ES. | M |
| P7-T6 | Source management REST API. All 7 source endpoints from 6.2. Snippet generation templates for each source type (TOML, YAML, rsyslog conf, pfSense instructions). Parser test endpoint runs sample log through normalization pipeline and returns ECS output. | `internal/sources/api_handlers.go`, `internal/sources/snippets/` | All endpoints return correct JSON. Snippet for EDR source returns valid TOML. Parser test with iptables log returns correct ECS fields. Parser test with garbage input returns descriptive error. | L |
| P7-T7 | Source onboarding wizard UI. Multi-step modal: source type selector (card grid), type-specific configuration form, snippet display with copy button, live verification panel with polling. Integrates with Sources page via "Add Source" button. | `web/src/components/SourceWizard.jsx`, `web/src/components/SourceWizardSteps/`, `web/src/components/SnippetDisplay.jsx` | Wizard opens from Sources page. Selecting EDR → shows EDR config fields. Submit → source created, snippet displayed. Verification polls and detects first event within 10s of event arrival. Skip verification works. | XL |
| P7-T8 | Sub-parser test interface. Textarea for sample log line, sub-parser dropdown, "Test" button, results panel showing parsed ECS fields or error. Accessible from onboarding wizard Step 2 (syslog types) and as standalone tool in Sources page. | `web/src/components/ParserTester.jsx` | Paste iptables log + select iptables parser → correct ECS fields displayed. Paste auditd log + select iptables parser → parse error or incorrect fields shown. Dropdown populated from available parsers on disk. | M |
| P7-T9 | Source health page. 3 KPI cards (Total EPS, Active Sources, Error Rate). Ingestion rate area chart with anomaly band. Source health TanStack Table with status dots, EPS sparklines, expandable detail rows. Integrated "Add Source" button linking to wizard. | `web/src/pages/Sources.jsx`, `web/src/components/SourceHealthTable.jsx`, `web/src/components/IngestionChart.jsx` | Correct metrics. Sparklines render. Expandable rows show error log and latency histogram. Error sources highlighted. Add Source opens wizard. | M |
| P7-T10 | Rules page. Detection Rules list (TanStack Table grouped by MITRE tactic with collapsible sections, enabled toggle, hit count, last triggered). ATT&CK Coverage heatmap (Nivo `<ResponsiveHeatMap>`, 14 tactic columns, three-tier coverage states, interactive cells, compact/expanded toggle, coverage percentages, Navigator JSON export). Tab toggle between list and heatmap views. | `web/src/pages/Rules.jsx`, `web/src/components/RulesList.jsx`, `web/src/components/AttackHeatmap.jsx` | Rules display grouped by tactic. Toggle enables/disables rule. Heatmap renders with correct coverage states. Click cell → popover with rule details. Export generates valid Navigator JSON. | XL |
| P7-T11 | User data model and auth service. ES indices for users (`akeso-users`) and sessions (`akeso-sessions`). Go structs for user and session. bcrypt password hashing (cost 12). JWT access token generation/validation (15min expiry). Refresh token storage in ES with revocation. Auth middleware that accepts JWT Bearer token or API key — dual auth so existing ingestion/CLI integrations are unaffected. | `internal/auth/types.go`, `internal/auth/service.go`, `internal/auth/jwt.go`, `internal/auth/middleware.go`, `internal/store/user_index.go` | Create user → password hashed. Login with correct password → JWT issued. Login with wrong password → 401. Access token expires after 15min. Refresh token issues new access token. Logout revokes refresh token. All dashboard API endpoints return 401 without valid auth. Ingestion endpoints still accept API key. | L |
| P7-T12 | TOTP MFA implementation. Secret generation, QR code URI encoding (`otpauth://` format), TOTP validation (RFC 6238, 30s window with ±1 window tolerance). MFA secret encrypted at rest with server-side key from akeso.toml. Enrollment: generate → verify → enable. Disable: require current password. CLI `akeso-cli users reset-mfa` command for admin recovery. | `internal/auth/mfa.go`, `internal/auth/totp.go`, `cmd/akeso-cli/commands/users.go` (extend) | Enroll MFA → QR code URI valid in Google Authenticator. Enter correct TOTP → authenticated. Enter wrong TOTP → rejected. ±1 window tolerance works. `akeso-cli users reset-mfa jsmith` → MFA disabled. Secret encrypted in ES document. | M |
| P7-T13 | Auth REST API. All 9 auth endpoints: login (password → optional MFA → tokens), refresh, logout, profile read/update, password change, MFA enroll/verify/disable. Rate limiting on login endpoint (5 attempts per 30s per IP). | `internal/auth/api_handlers.go` | Full login flow works (with and without MFA). Refresh issues new access token. Logout invalidates refresh. Password change works. MFA enrollment full cycle works. 6th failed login in 30s → 429 response. | M |
| P7-T14 | Login page + MFA page + auth guard + Settings profile section. Login page with username/password form, error states, AkesoSIEM branding (dark mode palette). MFA page with 6-digit input and auto-submit on 6th digit. React Router auth guard with silent refresh on mount — unauthenticated requests redirect to `/login`. Settings profile section: display name, password change form, MFA toggle with QR code enrollment modal. Header user avatar dropdown with profile link and sign out. Zustand auth store for token and user state. First-run detection: if no users exist, redirect to one-time admin setup page. | `web/src/pages/Login.jsx`, `web/src/pages/MFAVerify.jsx`, `web/src/pages/FirstRunSetup.jsx`, `web/src/components/AuthGuard.jsx`, `web/src/components/UserMenu.jsx`, `web/src/components/MFAEnrollModal.jsx`, `web/src/pages/Settings.jsx` (extend), `web/src/stores/authStore.js` | Login → dashboard. Wrong password → error. MFA enabled → MFA page after password. Correct TOTP → dashboard. Token expiry → silent refresh. Refresh expired → login redirect. Sign out → login page. Password change works. MFA enroll shows QR, verification completes enrollment. First run → admin setup page. | XL |
| P7-T15 | Playwright headless browser E2E test suite. Test all critical dashboard workflows against a running SIEM instance (Docker Compose + seeded test data). Test suites: **Auth flows** (login, wrong password error, MFA challenge, token refresh, logout, first-run setup). **Alert triage** (page loads, sort, filter, flyout opens with 3 tabs, acknowledge, bulk select, escalate to case). **Hunt page** (query bar accepts input, autocomplete dropdown appears, execute query returns results, time picker changes range, expandable row shows Table/JSON/Raw tabs, right-click context menu renders). **Cases** (case queue loads, flyout opens with 4 tabs, add comment appears in timeline, status change reflected, close requires resolution). **Sources** (health page loads with status indicators, onboarding wizard opens, step navigation works, snippet displays with copy button). **Rules** (rules list loads grouped by tactic, toggle enable/disable, ATT&CK heatmap renders, cell click opens popover). **Overview** (KPI cards render with values, charts render, NDR Host Risk Panel displays). **Dark mode** (toggle switches theme, persists across navigation). **Global search** (type IP → "IP" badge + grouped results, click Events → Hunt page with query, `/alerts` command navigates, `Cmd+Shift+P` opens command palette, recent searches appear on empty focus, Escape closes dropdown). **Time picker** (click opens dropdown, select preset updates button label, data re-fetches across pages, auto-refresh toggle works). All tests run headless in CI via `npx playwright test`. | `web/tests/e2e/auth.spec.ts`, `web/tests/e2e/alerts.spec.ts`, `web/tests/e2e/hunt.spec.ts`, `web/tests/e2e/cases.spec.ts`, `web/tests/e2e/sources.spec.ts`, `web/tests/e2e/rules.spec.ts`, `web/tests/e2e/overview.spec.ts`, `web/tests/e2e/theme.spec.ts`, `web/tests/e2e/search.spec.ts`, `web/tests/e2e/timepicker.spec.ts`, `web/playwright.config.ts`, `web/tests/e2e/fixtures/seed.ts` | All 10 test suites pass headless in CI. Auth flow: login → dashboard → logout round-trip completes. Alert triage: full flyout interaction works. Hunt: query execution returns results, context menu renders. Cases: comment → timeline → close workflow completes. Sources: wizard step navigation works end-to-end. Rules: heatmap renders without JS errors. Global search: entity search returns grouped results, command palette navigates. Time picker: preset change triggers data re-fetch. Tests run against Docker Compose with seeded test data via `make test-e2e`. Total: ≥50 E2E test cases across 10 suites. | L |
| P7-T16 | Global search API. `GET /api/v1/search` endpoint with type auto-detection (IP, SHA-256, SHA-1, MD5, Community ID, domain, file path, username, case/alert ID, free text), parallel `_msearch` across events/alerts/cases/host-scores/rules indices, grouped response format with counts and source-type breakdowns, time-range scoping from global time picker state, per-group result limit. | `internal/query/search_handler.go`, `internal/query/type_detector.go` | IP search returns grouped results from all indices. Hash search targets correct `file.hash.*` field. Community ID search returns NDR sessions + EDR events. Event group returns count + source breakdown (not full docs). Empty query → 400. Results respect global time range for events/alerts. Response under 200ms for single-term queries. | M |
| P7-T17 | Global search UI + command palette + time picker. Replace header search placeholder with full search component: type-detection badge (inline, updates on keystroke), results dropdown with grouped categories (host score → alerts → cases → events → rules), click-through routing to Hunt (pre-built query), Alerts (filtered + flyout), Cases (filtered + flyout), host score detail, and Rules (highlighted). Command palette mode via `/` or `Cmd+Shift+P` with fuzzy-matched navigation and quick actions. Recent searches panel (localStorage, keyed to user). Replace header time picker placeholder with functional `TimePicker.jsx` component (shared with Hunt page): quick-select presets, absolute range picker, auto-refresh toggle. Time range stored in Zustand, consumed by all TanStack Query hooks via query invalidation. | `web/src/components/GlobalSearch.jsx`, `web/src/components/SearchResults.jsx`, `web/src/components/CommandPalette.jsx`, `web/src/components/RecentSearches.jsx`, `web/src/hooks/useTypeDetection.js`, `web/src/components/TimePicker.jsx`, `web/src/stores/timeRangeStore.js` | Type any IP → "IP" badge appears, results show host score + alerts + events grouped. Type any hash → "SHA-256" badge, events group shows AV + EDR results. Click Events group → Hunt page opens with correct query. `/alerts` → navigates to Alerts page. `Cmd+Shift+P` opens command mode. Recent searches shown on empty focus. Escape closes dropdown. Time picker: click → dropdown opens, select "Last 1h" → button label updates, Overview KPIs and charts re-fetch, Hunt page time range synced. Auto-refresh toggle shows animated indicator when active. | XL |

---

### Phase 8: CLI & Operations

**Goal:** Management CLI.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P8-T1 | CLI: health, query, alerts, rules, keys, sources, users. `--json` flag. Users subcommands: `users create`, `users list`, `users disable`, `users reset-mfa`. | `cmd/akeso-cli/main.go`, `commands/*.go` | All subcommands work. JSON output. `users create --username jsmith --display-name "John Smith"` → user created. `users list` → table of users. `users reset-mfa jsmith` → MFA disabled. | M |
| P8-T2 | `rules update`: git pull + validate + hot-reload + rollback. `--init`. | `commands/rules_update.go` | New rule active. Bad rule rolls back. | M |
| P8-T3 | `ingest test` + `ingest replay <file>`. | `commands/ingest_test.go` | Test event in ES. Replay indexes all events. | S |
| P8-T4 | CLI source management. `akeso-cli sources add`, `sources list`, `sources remove`, `sources test-parser`. The `add` subcommand mirrors the wizard flow in non-interactive mode (flags for all fields) and prints the configuration snippet to stdout. | `cmd/akeso-cli/commands/sources.go` | `sources add --type AkesoEDR --name "Lab EDR"` → source created, snippet printed. `sources list` → table of sources with health. `sources test-parser --parser iptables --log "<log line>"` → ECS output. `--json` flag works on all subcommands. | M |

---

### Phase 9: Case Management

**Goal:** Built-in case management for alert escalation, observable tracking, and incident resolution.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P9-T1 | Case data model and ES index. Define Go structs for case, observable, timeline entry. Index template with ECS-compatible mappings. ILM policy (365-day retention, matching alert retention). | `internal/cases/types.go`, `internal/store/case_template.go` | Structs compile. Template created in ES. Round-trip marshal/unmarshal. ILM policy applied. | M |
| P9-T2 | Case CRUD service. Create, read, update, list, close. Status transition validation (cannot skip states). Resolution required on close. Optimistic concurrency via ES version. | `internal/cases/service.go` | Create case → read returns it. Invalid status transition → error. Close without resolution → error. Concurrent update → conflict error. | L |
| P9-T3 | Observable extractor. Extract IPs, file hashes (MD5/SHA1/SHA256), usernames, domains, and process names from ECS-normalized events. Deduplicate by (type, value). Tag with source alert ID. | `internal/cases/observable_extractor.go` | Network alert → IP observables. File alert → hash observables. DLP alert → username + file path. Cross-source case → merged deduplicated observables. | M |
| P9-T4 | Alert-to-case escalation pipeline. Single alert and bulk escalation. Auto-populate title, severity, observables, MITRE tags. Update alert status to "Escalated" with case back-reference. | `internal/cases/escalation.go`, `internal/alert/alert_pipeline.go` (modify) | Escalate 1 alert → case created with correct fields. Escalate 5 alerts → all linked, observables merged. Alert status updated to Escalated. | L |
| P9-T5 | Case REST API. All 8 case endpoints from Section 6.2. JSON responses. Pagination. Filter/sort. Input validation. | `internal/cases/api_handlers.go` | All endpoints return correct JSON. Invalid input → 400 with descriptive error. Pagination works. Stats endpoint returns accurate metrics. | M |
| P9-T6 | Alert merge and timeline. Merge additional alerts into existing case. Deduplicate observables. Log all analyst actions (comments, status changes, merges, observable additions) to case timeline. | `internal/cases/merge.go`, `internal/cases/timeline.go` | Merge 3 alerts into existing case → case.alert_ids has all IDs, new observables added, merge logged in timeline. Add comment → appears in timeline with timestamp and author. | M |
| P9-T7 | Cases dashboard page. Case queue table (TanStack Table), case detail flyout with 4 tabs (Overview, Alerts, Observables, Timeline), case actions (assign, status, comment, merge, close). Observable pivot actions reuse Hunt page context menu. | `web/src/pages/Cases.jsx`, `web/src/components/CaseFlyout.jsx`, `web/src/components/CaseTimeline.jsx`, `web/src/components/ObservableList.jsx` | Cases page loads, displays queue. Click row → flyout opens with all tabs. Status change → reflected in queue. Comment added → appears in timeline. Close → resolution modal enforced. | XL |

---

### Phase 10: Integration Testing

**Goal:** End-to-end validation across all six source types.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P10-T0 | Complete scenario library (all 8 scenarios: credential_theft, lateral_movement, data_exfiltration, malware_delivery, full_kill_chain, insider_threat, brute_force, ransomware — each producing events across multiple source types including NDR). Generate full demo dataset (50K+ events, 24h simulated window, 50 hosts, all 6 source types). Validate all scenarios trigger expected Sigma rules including NDR cross-portfolio rules, with zero FPs from noise. Wire into `make demo` target. | `tools/scenarios/*.yaml` (remaining 5), `tests/generated/demo_dataset.ndjson`, `Makefile` (demo target) | All 8 scenarios produce expected alerts. Full demo dataset: 50K+ events, 40–60 alerts, 8–12 cross-source correlations (including NDR), 0 FPs. `make demo` replays dataset and populates dashboard with realistic data across all pages including NDR Host Risk Panel. | L |
| P10-T1 | Load 50 curated SigmaHQ rules + 5 cross-portfolio rules + 5 NDR cross-portfolio rules. Verify parse + load. | `rules/sigma_curated/`, `rules/akeso_portfolio/` | 60 rules loaded. CLI lists all with metadata. | M |
| P10-T2 | Replay 850 events across all 6 source types (AkesoEDR, AkesoAV, AkesoDLP, AkesoNDR, Windows Events, syslog) including 40 events that should trigger loaded rules. | `tests/integration/test_events.json`, `replay_test.go` | All indexed. Exactly 40 alerts. Zero FPs from benign events. | L |
| P10-T3 | Cross-source temporal correlation: "EDR credential theft alert → NDR lateral movement detection → EDR outbound data transfer, correlated by source.ip within 30 min." | `rules/test_cross_portfolio.yml`, `correlation_test.go` | Temporal rule fires across AkesoEDR + AkesoNDR sources. Events from same host correlated correctly. | L |
| P10-T4 | Cross-product validation: "NDR detects SMB file transfer to Host X → AV shows file is malicious on Host X → EDR shows process that dropped the file → Windows Event shows the user who launched the process." Four sources, one incident. | `rules/test_ndr_av_edr_winevt.yml`, `tests/integration/cross_product_test.go` | Correlation links NDR, AV, EDR, and Windows Event telemetry into a single alert with observables from all four sources. | L |
| P10-T5 | Case management end-to-end. Cross-portfolio rule → alert → escalate to case → case created with observables from multiple sources including NDR network metadata (Community IDs, JA3 fingerprints). | `tests/integration/case_management_test.go` | Alert escalated to case. Case contains observables extracted from EDR events (process, IPs), AV events (file hashes, signature names), DLP events (classification, policy), and NDR events (Community ID, JA3/JA4, detection name, host score). Timeline shows escalation event. | M |
| P10-T6 | NDR dual logsource validation. Verify that SigmaHQ community DNS rule fires on NDR DNS event. Verify community TLS rule fires on NDR TLS event. Verify `product: akeso_ndr` rule does NOT fire on non-NDR events. | `tests/integration/ndr_logsource_test.go` | Community `category: dns` rule fires on `ndr:dns` event. `product: akeso_ndr` rule fires only on NDR events. No cross-contamination. | M |
| P10-T7 | NDR full-chain correlation test. Replay 4-event attack scenario: NDR port scan → EDR LSASS access → NDR SMB lateral movement → NDR data exfiltration. Verify the full-chain temporal rule fires with all 4 events linked. | `rules/test_ndr_full_chain.yml`, `tests/integration/ndr_full_chain_test.go` | Full-chain temporal correlation fires. Alert includes event IDs from all 4 stages. MITRE tags: T1046, T1003, T1021.002, T1041. | L |

---

### Phase 11: Hardening & Performance

**Goal:** Production readiness.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P11-T1 | Graceful shutdown. Drain, flush, save state, close. | All `cmd/*/main.go` | SIGTERM → clean exit <10s. No event loss. | M |
| P11-T2 | Prometheus metrics. Events ingested, indexed, alerts, latency, queue depth. | `internal/common/metrics.go` | Prometheus scrapes. Grafana template. Accurate. | L |
| P11-T3 | Load test. 1000 eps × 10 min. Measure latency, eval time, memory. | `tests/benchmark/load_test.go` | 1000 eps sustained. p95 <5s. Eval <10ms/event. No leaks. | L |
| P11-T4 | Dead letter queue. Failed events → DLQ index. Failed alerts → retry queue. | `internal/ingest/dead_letter.go`, `internal/alert/retry_queue.go` | Malformed → DLQ. Alert pipeline timeout → retry → DLQ after 3 fails. | M |
| P11-T5 | Deployment automation. `make install` builds all binaries + dashboard, starts Docker Compose, applies ES templates/ILM, creates initial admin user via CLI, prints credentials + API key + dashboard URL. `make dev` for hot-reload development. `make demo` for portfolio demos (install + create demo analyst accounts + replay full demo dataset + trigger correlation rules + pre-assign demo cases to different analysts + open dashboard). `make clean` for reset. | `Makefile`, `scripts/install.sh`, `scripts/demo.sh`, `docker-compose.yml` (update), `akeso.toml.template` | `make install` → dashboard accessible, admin credentials printed, API key printed, CLI works. `make demo` → 50K+ events in ES, alerts fired, cases available with multi-analyst attribution, NDR host scores populated, dashboard fully populated across all pages. Login with admin credentials works. `make clean` → clean state. `make dev` → hot-reload works for Go and React. | M |
| P11-T6 | File-based server logging. Extend zap logger configuration to write structured JSON logs to disk in addition to stdout. Configurable via `akeso.toml` (`[logging]` section): log directory path (default: `/var/log/akeso/`), per-binary log files (`akeso-ingest.log`, `akeso-correlate.log`, `akeso-query.log`), max file size before rotation (default: 100MB), max rotated file count (default: 10), max age in days (default: 30), and compression of rotated files (default: gzip). Log level configurable per binary (debug/info/warn/error). Stdout output remains enabled by default for Docker/dev workflows — file logging is additive. `make install` creates the log directory with appropriate permissions. | `internal/common/logger.go` (extend), `akeso.toml` (`[logging]` section), `scripts/install.sh` (add log dir creation) | All binaries write structured JSON logs to configured directory. Log rotation triggers at 100MB, old files compressed. `tail -f /var/log/akeso/akeso-ingest.log` shows live structured logs. Setting `log_level = "debug"` increases verbosity. Disabling file logging (`file_enabled = false`) falls back to stdout-only. Log directory created by `make install` with correct ownership. | M |

---

### Phase 12: AI Investigation Assistant

**Goal:** AI-powered investigation assistant integrated into the dashboard, using the SIEM's REST API as its tool set.

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P12-T1 | Agent tool schema definitions. Define all 13 tools from Section 11.2 as Anthropic tool-use JSON schemas. Map each tool to the corresponding SIEM REST API fetch call. Error handling for API failures returns descriptive error to model. | `web/src/agent/tools.js`, `web/src/agent/tool_executor.js` | All 13 tools have valid schemas. Tool executor calls correct API endpoint including host-scores endpoints. Returns parsed JSON to model. API errors handled gracefully. | M |
| P12-T2 | System prompt engineering. Write system prompt covering Akeso portfolio context (including AkesoNDR capabilities, protocol metadata, host scoring, behavioral detections), ECS field reference (including all `ndr.*` fields), query syntax grammar, Sigma rule structure, MITRE ATT&CK context, Community ID cross-source correlation patterns, and investigation methodology. Store as markdown loaded at runtime. | `web/src/agent/system_prompt.md`, `web/src/agent/prompt_loader.js` | System prompt loads. Agent correctly generates SIEM queries from natural language including NDR fields. Agent correctly interprets Sigma rule YAML. Agent references correct ECS field names including `ndr.*` extensions. Agent uses `get_host_scores` tool when investigating network-layer threats. | L |
| P12-T3 | Anthropic API client with streaming. Implement messages API with tool_use, streaming response handling, and multi-turn conversation management. Handle tool call → tool result → continue loop. Rate limits and error states. | `web/src/agent/anthropic_client.js`, `web/src/agent/conversation.js` | Streaming tokens render in real time. Tool calls execute and return results. Multi-turn conversation maintains context. API errors show user-friendly message. | L |
| P12-T4 | Assistant panel UI. Slide-out panel with header, message stream (markdown rendering, tool call cards), input bar, and quick action buttons. Context injection based on active page/entity. Zustand store for conversation state. | `web/src/components/AssistantPanel.jsx`, `web/src/components/AssistantMessage.jsx`, `web/src/components/ToolCallCard.jsx`, `web/src/stores/assistantStore.js` | Panel opens/closes from header icon. Messages render with markdown. Tool calls show as collapsible cards. Context pre-loaded from active page. Quick action buttons trigger pre-defined prompts. | XL |
| P12-T5 | "Copy to..." action handlers. Copy to Hunt (inject query into query bar), Copy to Case Comment (POST to case timeline API, attributed to "AkesoAI"), Copy Sigma Rule (modal with syntax highlighting + save), Copy to Clipboard. | `web/src/agent/actions.js`, `web/src/components/SigmaRuleModal.jsx` | Copy to Hunt populates query bar. Copy to Case Comment creates timeline entry. Copy Sigma Rule shows valid YAML in modal. Clipboard copy works. | M |
| P12-T6 | Query assistance mode. Agent generates SIEM query syntax from natural language, validates against grammar, offers "Copy to Hunt" action. Reverse mode: paste a query, agent explains it in plain language. | `web/src/agent/modes/query_assist.js` | Natural language → valid SIEM query. Query → plain English explanation. Generated queries return results when executed. Invalid queries detected with corrections. | M |
| P12-T7 | Alert triage mode. Agent summarizes alert: what fired, why, process chain, cross-source context, risk assessment, recommended actions. Multi-step tool use (get_alert → search related events → lookup observables). | `web/src/agent/modes/alert_triage.js` | "Explain this alert" produces accurate summary. Agent identifies process parent chain. Agent checks cross-source events (AV/DLP) for same host/user. Recommendations are actionable. | L |
| P12-T8 | Investigation copilot mode. Multi-step investigation: scope → timeline → lateral movement check → data exposure check → observable enrichment → narrative. Streams each step. Analyst can interrupt and redirect. | `web/src/agent/modes/investigation.js` | "What happened here?" produces structured investigation. Each step visible via tool call cards. Agent queries across EDR, AV, DLP, and NDR events. Narrative includes timeline and recommendations. Interruption works. | XL |
| P12-T9 | Detection rule drafting mode. Agent generates Sigma YAML from natural language pattern description. Correct logsource mapping, field names, modifiers, MITRE tags. Optionally tests against historical data via search_events. | `web/src/agent/modes/rule_draft.js` | Generated Sigma YAML parses without error. Logsource mapping correct. MITRE tags match described technique. Historical test returns hit count and sample matches. | L |
| P12-T10 | Integration testing. 6 end-to-end scenarios: (1) Natural language query → results. (2) Alert explanation with cross-source context. (3) Case investigation with multi-step tool use. (4) Sigma rule generation + historical validation. (5) Cross-portfolio attack narrative from full-chain correlation alert including NDR network telemetry. (6) NDR host score assessment — agent queries host scores, identifies Critical hosts, explains active NDR detections and recommends investigation steps. | `tests/integration/agent_test.js` | All 6 scenarios produce correct output. Tool calls hit correct endpoints including host-scores. Streaming renders without errors. No hallucinated field names or query syntax. Cross-portfolio narrative correctly attributes events to EDR/AV/DLP/NDR sources with network session metadata. | L |

---

## Phase Summary

| Phase | Name | Tasks | Depends On | Focus |
|-------|------|-------|------------|-------|
| P0 | Scaffolding | 6 | — | Foundation |
| P1 | HTTP + AkesoEDR | 5 | P0 | Ingestion |
| P1a | AkesoAV & DLP Parsers | 4 | P1 | Ingestion |
| P1b | AkesoNDR Parser | 5 | P1 | Ingestion |
| P2 | Windows Events | 4 | P1 | Ingestion |
| P3 | Syslog | 4 | P1 | Ingestion |
| P4 | Sigma Single-Event | 5 | P1 | Detection |
| P5 | Sigma Correlation | 5 | P4 | Detection |
| P6 | Query + API | 4 | P0, P1 | Hunting |
| P7 | Dashboard + Sources + Auth | 17 | P6 | Interface + Authentication |
| P8 | CLI | 4 | P0–P7 | Operations |
| P9 | Case Management | 7 | P4, P7 | Response + Investigation |
| P10 | Integration Tests | 8 | All | Validation |
| P11 | Hardening | 6 | All | Production |
| P12 | AI Investigation Assistant | 10 | P6, P7, P9 | AI-Augmented Investigation |

**Total: 94 tasks, 15 phases. Estimated 65–91 Claude Code sessions.**

---

## Code Conventions

### Go
Go 1.22+. Standard library preferred. Errors wrapped with `fmt.Errorf`. Context propagation. Structured JSON logging (zap). Table-driven tests.

### Elasticsearch
ECS field mappings on all indices. Bulk indexing (batch 500, flush 5s). ILM for retention.

### Sigma Rules
Git-managed `rules/` dir. Hot-reload, atomic swap. Logsource mapping configurable. Validation on load.

### Dashboard
React + Tailwind CSS. Component isolation. TanStack Query for all server state. Zustand for minimal client state. Headless UI for accessible primitives. CodeMirror 6 for query editor. Inter font at 500 weight. **Testing:** Playwright for headless browser E2E tests against a running instance with seeded data. All critical workflows (auth, triage, hunting, cases, sources, rules) validated end-to-end. Tests run headless in CI via `make test-e2e`. Vitest for component unit tests where E2E coverage is insufficient.

---

## v2 Roadmap

- ML anomaly detection: behavioral baselines per user/host.
- SOAR integration: automated response playbooks (trigger AkesoEDR ISOLATE on critical alert, trigger AkesoFW block on critical NDR alert).
- Multi-tenant: separate data + rules per org.
- Cloud sources: AWS CloudTrail, Azure AD, GCP Audit.
- Kibana integration: optional visualization layer.
- Rule authoring UI: create + test Sigma rules from dashboard.
- Enrichment pipeline: GeoIP, threat intel feeds, ASN at ingest time.
- Collection agent: lightweight Go agent for Linux/macOS log forwarding.
- NDR PCAP retrieval: proxy AkesoNDR's PCAP API so analysts can download detection PCAPs directly from the SIEM dashboard without switching tools.
- Community ID graph: visualization of all events sharing a Community ID — showing the full lifecycle of a network session from NDR metadata, through EDR process context, to firewall decisions.
- Email notifications: SMTP alerts on high/critical severity with configurable thresholds.
- Browser push notifications: via service worker triggered by SSE feed.
- Slack/Teams webhooks: alert channel integration for team visibility.
- AI assistant enhancements: autonomous triage (agent pre-triages low-severity alerts with analyst approval queue), threat intel enrichment via tool calls to VirusTotal/AbuseIPDB APIs, natural language report generation for executive summaries, NDR-aware investigation playbooks (agent automatically queries host scores and NDR detections when investigating network-involved incidents).