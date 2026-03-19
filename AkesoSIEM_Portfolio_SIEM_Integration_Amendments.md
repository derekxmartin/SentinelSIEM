# Akeso Portfolio — SIEM Integration Amendments
## Additions to akeso_edr, AkesoAV, and AkesoDLP Requirements Documents
**March 2026**

These amendments add a SIEM output writer to each Akeso portfolio tool so they can ship telemetry to AkesoSIEM's `/api/v1/ingest` endpoint. Each amendment is designed to be inserted into the respective project's requirements document at the indicated location.

---

## 1. akeso_edr Amendment

### 1.1 Insert into Section 3.2 (Telemetry Protocol)

Add the following paragraph after the existing named pipe description:

> **SIEM output mode:** In addition to local JSON file logging and the named pipe, the agent supports an optional HTTP POST output sink targeting AkesoSIEM's ingest endpoint. When enabled, the agent's event processing pipeline forks: events flow to both the local log and the SIEM output writer. The SIEM writer serializes `SENTINEL_EVENT` structs into the JSON envelope format defined in AkesoSIEM Appendix A (common envelope with `source_type: "akeso_edr"`, `event_type` mapped from the sensor source identifier, and `payload` containing the sensor-specific fields). Events are batched as NDJSON and flushed on a configurable interval or batch size threshold. On SIEM unavailability, events are buffered to a local spill file and drained on reconnect. The SIEM output is independent of the v2 `sentinel-server` TLS push — both can be active simultaneously.

### 1.2 Insert into Section 3.4 (Signature Updates) or create new Section 3.5

> **SIEM Integration Configuration**
>
> The agent config file (`akeso.conf`) gains an `[output.siem]` section:
>
> ```toml
> [output.siem]
> enabled = false
> endpoint = "https://siem.local:8443/api/v1/ingest"
> api_key = "sk-xxxxxxxxxxxxxxxxxxxx"
> batch_size = 100          # events per HTTP POST
> flush_interval_ms = 5000  # max time before flush
> spill_path = "C:\\ProgramData\\akeso_edr\\siem_spill.ndjson"
> spill_max_mb = 512        # max spill file size
> tls_verify = true         # verify SIEM server certificate
> source_type = "akeso_edr"
> ```

### 1.3 Event Type Mapping

The SIEM writer maps `SENTINEL_EVENT.source` enum values to the `event_type` string in the JSON envelope:

| SENTINEL_EVENT.source | JSON event_type |
|----------------------|-----------------|
| `drv:process_create` | `edr:process_create` |
| `drv:process_terminate` | `edr:process_terminate` |
| `drv:thread_create` | `edr:thread_create` |
| `drv:object_handle` | `edr:object_handle` |
| `drv:image_load` | `edr:image_load` |
| `drv:registry_*` | `edr:registry_modify` |
| `mf:file_create` / `mf:file_write` | `edr:file_create` |
| `wfp:connect` / `wfp:accept` | `edr:network_connect` |
| `hook:Nt*` | `edr:api_hook` |
| `etw:*` | `edr:etw_event` |
| `amsi:scan` | `edr:amsi_scan` |
| `scanner:yara_match` | `edr:scanner_alert` |

### 1.4 Implementation Task — Add to Phase 9 (CLI & Config)

Insert as **P9-T5**:

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P9-T5 | SIEM output writer. HTTP POST client for NDJSON batches to configurable endpoint. API key auth via `X-API-Key` header. Batch accumulation with size + time flush triggers. Spill-to-disk on SIEM unavailability. Drain on reconnect. Config in `[output.siem]` section. JSON serializer converts `SENTINEL_EVENT` to AkesoSIEM Appendix A envelope format. | `sentinel-agent/output/siem_writer.cpp`, `sentinel-agent/output/siem_writer.h`, `sentinel-agent/output/siem_serializer.cpp` | `enabled = true` → events arrive at SIEM endpoint as valid NDJSON. `enabled = false` → no HTTP calls. SIEM down → events spill to disk, no data loss. SIEM back → spill drains. Batch of 100 events sends as single POST. Invalid API key → logged error, events spilled. | L |

### 1.5 Impact on Phase Summary

Phase 9 goes from 4 tasks to 5. Total project goes from 49 to 50 tasks. The SIEM writer depends on the config system (P9-T3) and the JSON logging infrastructure (P4-T3), both of which already exist in the plan.

---

## 2. AkesoAV Amendment

### 2.1 Insert into Section 7.2 (Daemon) or create new Section 7.5

> **7.5 SIEM Output Writer**
>
> The daemon (`savd`) and real-time filesystem monitor gain an optional SIEM output mode. When enabled, scan results and operational events (quarantine, real-time block, signature update, scan error) are serialized into the JSON envelope format defined in AkesoSIEM Appendix A (common envelope with `source_type: "akeso_av"`, `event_type` per event category, and `payload` containing fields derived from `sav_scan_result_t` plus daemon/monitor metadata).
>
> Events are shipped via HTTP POST to AkesoSIEM's `/api/v1/ingest` endpoint as NDJSON batches. Authentication is via `X-API-Key` header. On SIEM unavailability, events are buffered to a local spill file and drained on reconnect.
>
> **Which events are forwarded:**
> - `av:scan_result` — All detections (malicious + suspicious). Clean results are not forwarded by default (configurable).
> - `av:quarantine` — All quarantine actions.
> - `av:realtime_block` — All real-time blocks from the filesystem monitor.
> - `av:signature_update` — Signature database updates.
> - `av:scan_error` — Scan failures (timeout, access denied, parser crash). Per AkesoAV's fail-closed design, these are security-relevant.
>
> The CLI scanner (`savscan`) does not ship events to the SIEM directly — it writes results to stdout/file. To ingest CLI scan results, pipe JSON output to `akeso-cli ingest replay`.

### 2.2 Configuration

Add to daemon config (`savd.conf` or equivalent):

```toml
[siem]
enabled = false
endpoint = "https://siem.local:8443/api/v1/ingest"
api_key = "sk-xxxxxxxxxxxxxxxxxxxx"
batch_size = 50
flush_interval_ms = 5000
spill_path = "/var/lib/akesoav/siem_spill.ndjson"
spill_max_mb = 256
tls_verify = true
source_type = "akeso_av"
forward_clean_results = false   # set true to send all scan results including clean
```

### 2.3 Event Type Mapping

The SIEM writer maps internal events to `event_type` strings:

| Internal Event | JSON event_type | Trigger |
|---------------|-----------------|---------|
| Scan result with `found = true` | `av:scan_result` | Any detection (signature, heuristic, YARA) |
| File moved to quarantine vault | `av:quarantine` | Quarantine action after detection |
| fanotify/minifilter permission denied | `av:realtime_block` | Real-time monitor blocks file create/exec |
| `sav_update_signatures()` success | `av:signature_update` | Signature DB updated |
| `sav_scan_file()` returns `SAV_ERROR_*` | `av:scan_error` | Timeout, I/O error, parser failure |

### 2.4 Serialization: `sav_scan_result_t` → JSON Envelope

The serializer maps C struct fields to JSON payload fields:

| `sav_scan_result_t` field | JSON payload path | Notes |
|--------------------------|-------------------|-------|
| `found` | Determines `scan.result` | `true` → `"malicious"` or `"suspicious"` (based on `heuristic_score` threshold) |
| `malware_name[256]` | `signature.name` | |
| `signature_id[64]` | `signature.id` | |
| `scanner_id[64]` | `scan.scanner_id` | `"savscan"`, `"savd"`, or `"realtime"` |
| `file_type[32]` | `file.type` | PE32, ELF, PDF, ZIP, etc. |
| `heuristic_score` | `scan.heuristic_score` | 0.0 for signature-only, 0.0–1.0 for heuristic |
| `in_whitelist` | `file.in_whitelist` | |
| `total_size` | `file.size` | |
| (from scan context) | `file.path`, `file.name`, `file.hash.*` | Path and hashes from scan input, not from result struct |
| (from daemon) | `scan.scan_type`, `scan.duration_ms` | `on_demand`, `on_access`, `memory` |
| (from monitor) | `process.pid`, `process.name`, `process.executable` | Only populated for on-access and memory scans |

### 2.5 Implementation Task — Add to Phase 2 (Detection Depth)

Insert as a new task in Phase 2 (where the daemon and real-time monitor are built):

| ID | Task | Files | Acceptance Criteria | Est. |
|----|------|-------|---------------------|------|
| P2-T_SIEM | SIEM output writer for daemon and real-time monitor. HTTP POST client for NDJSON batches. Serializer converts `sav_scan_result_t` + scan context to AkesoSIEM Appendix A JSON envelope. Spill-to-disk on SIEM unavailability. Config in `[siem]` section. | `src/output/siem_writer.cpp`, `src/output/siem_writer.h`, `src/output/siem_serializer.cpp` | `enabled = true` → detections arrive at SIEM as valid NDJSON with all required fields. Quarantine → `av:quarantine` event. Real-time block → `av:realtime_block` event with process context. Signature update → `av:signature_update` event. SIEM down → spill, no data loss. | M |

### 2.6 Impact on Phase Summary

Phase 2 gains 1 task. The SIEM writer is M complexity because it's a straightforward HTTP client + JSON serializer — the hard work (daemon, monitor, scan pipeline) is already scoped in existing Phase 2 tasks. The serializer is simple field mapping with no business logic.

---

## 3. AkesoDLP Amendment

### 3.1 Insert into Task 4.4 (Syslog / SIEM Integration)

The DLP requirements already include a CEF syslog exporter in Task 4.4. Amend this task to also include a JSON/HTTP output writer for AkesoSIEM:

> **SIEM JSON Output (in addition to CEF syslog):**
>
> The DLP server gains an HTTP POST output writer that ships incidents to AkesoSIEM's `/api/v1/ingest` endpoint as NDJSON batches. Each incident is serialized into the JSON envelope format defined in AkesoSIEM Appendix A (common envelope with `source_type: "akeso_dlp"`, `event_type` per incident category, and `payload` containing policy, violation, file, user, destination, and response fields).
>
> The writer is triggered on incident creation in the DLP server's incident pipeline — the same point where the CEF syslog exporter fires. Both outputs can be active simultaneously.
>
> Unlike the EDR and AV writers (which run in the agent process), the DLP SIEM writer runs in the **DLP server** (Python/FastAPI), not the Go endpoint agent. This is because the DLP server is the authoritative incident store — it aggregates agent reports, applies server-side detection (two-tier detection), and enriches incidents with policy metadata. Shipping from the server ensures the SIEM receives fully resolved incidents, not raw agent reports.

### 3.2 Configuration

Add to DLP server config (`config.yaml` or environment variables):

```yaml
siem:
  enabled: false
  endpoint: "https://siem.local:8443/api/v1/ingest"
  api_key: "sk-xxxxxxxxxxxxxxxxxxxx"
  batch_size: 25
  flush_interval_seconds: 10
  tls_verify: true
  source_type: "akeso_dlp"
  retry_max: 3
  retry_delay_seconds: 5
```

### 3.3 Event Type Mapping

The SIEM writer maps DLP incident types to `event_type` strings:

| DLP Incident Type | JSON event_type | Source |
|------------------|-----------------|--------|
| Policy violation (any channel) | `dlp:policy_violation` | Agent endpoint detection or network monitor detection |
| Active block (endpoint or network prevent) | `dlp:block` | Block response action executed |
| File classification (Endpoint Discover) | `dlp:classification` | Discover scan result |
| Removable media activity | `dlp:removable_media` | Agent filesystem monitor (USB write) |
| Audit-only violation (log action) | `dlp:audit` | Policy with action=log |

### 3.4 Serialization: DLP Incident Model → JSON Envelope

The serializer maps the DLP server's PostgreSQL incident model to JSON payload fields:

| DLP Incident Field | JSON payload path | Notes |
|-------------------|-------------------|-------|
| `incident.policy_id`, `incident.policy_name` | `policy.id`, `policy.name` | |
| `incident.severity` | `policy.severity` | high, medium, low, info |
| `incident.response_action` | `policy.action` | log, block, notify, user_cancel |
| `incident.classification` | `violation.classification` | pii, phi, pci, confidential, etc. |
| `incident.channel` | `violation.channel` | usb, http_upload, smtp_email, etc. |
| `incident.source_type` | `violation.source_type` | endpoint, network |
| `incident.match_count` | `violation.match_count` | |
| `incident.detection_method` | `violation.detection_method` | regex, keyword, data_identifier, fingerprint, file_type |
| `incident.filename`, `incident.file_size` | `file.name`, `file.size` | |
| `incident.file_path` | `file.path` | Endpoint incidents only |
| `incident.file_hash` | `file.hash.sha256` | If available |
| `incident.user_identity` | `user.name` | |
| `incident.source_ip` | Network source IP | Network incidents only |
| `incident.destination` | `destination.*` or `network.url` | Channel-dependent: USB device ID, URL, email address |
| `incident.status` | `response.action_taken` | logged, blocked, notified, user_overridden |
| `incident.justification` | `response.user_justification` | If user_cancel action was taken |

### 3.5 Implementation

No new task is needed — the SIEM JSON writer is an extension of the existing Task 4.4 (Syslog / SIEM Integration). Amend the acceptance criteria for Task 4.4:

**Original acceptance criteria:** "Incident appears in SIEM with correct severity and event categorization."

**Amended acceptance criteria:** "CEF syslog incident appears in external SIEM with correct severity and categorization. JSON/HTTP incident arrives at AkesoSIEM `/api/v1/ingest` as valid NDJSON with all required Appendix A fields. Both outputs fire on the same incident. SIEM down → incidents queued in memory (max 1000), then spilled to disk. SIEM back → queue drains."

### 3.6 Impact on Phase Summary

No new tasks. Task 4.4 scope increases slightly (adds an HTTP client alongside the existing syslog client). The JSON serializer is simpler than the CEF formatter because it's a direct field mapping without CEF's fixed-format string construction.

---

## 4. Summary of Amendments

| Project | Amendment | New Tasks | Complexity | Config Section |
|---------|-----------|-----------|------------|----------------|
| akeso_edr | SIEM output writer in agent (C++) | +1 (P9-T5) | L | `[output.siem]` in akeso.conf |
| AkesoAV | SIEM output writer in daemon (C++) | +1 (P2-T_SIEM) | M | `[siem]` in savd.conf |
| AkesoDLP | Extend Task 4.4 syslog exporter (Python) | 0 (scope increase) | — | `siem:` in config.yaml |

All three writers share the same design pattern: NDJSON batch → HTTP POST → `X-API-Key` auth → spill-to-disk on failure → drain on reconnect. The serialization logic is project-specific (C struct mapping for EDR/AV, Python dict mapping for DLP), but the output format converges on the same AkesoSIEM Appendix A JSON envelope.

The AkesoSIEM parsers (Phase 1, 1a) are built against the synthetic test fixtures defined in Appendix A Section 7. When each tool implements its SIEM writer, the parsers work without modification because both sides conform to the same schema contract.
