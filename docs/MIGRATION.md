# Data & Architecture Migration Guide: Zero-Risk-Score Determinism

## 1. Architectural Transition Overview

This document outlines the migration from the prototype probabilistic risk-scoring model to the **Deterministic DNS Security Gateway**.

### Eliminated Components:
- **Risk Scoring Calculations**: Removed 0–100 risk score heuristics, threat percentages, and arbitrary severity thresholds (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Probabilistic Decisions**: Replaced anomaly score cutoffs with deterministic policy rules, validated threat feeds, and administrator-defined policies.
- **Ambiguous Tagging**: Eliminated labelling unknown domains as malicious; replaced with explicit classifications (`THREAT_BLOCKLIST`, `ADMIN_POLICY`, `RECORD_TYPE`, `RATE_LIMIT`, `ACCESS_DENIED`, `PROTOCOL_VIOLATION`, `ALLOWED`).

---

## 2. Telemetry Schema Transformation

Legacy telemetry in `data/events/dns_events.jsonl` contained statistical features, ML indices, and severity scores. The new architecture records strictly deterministic operational parameters in SQLite (`dns_logs` table).

| Legacy Field | New Schema Status | Migration Mapping |
| :--- | :--- | :--- |
| `risk_score` (0–100) | **REMOVED** | Purged from active workflow |
| `classification` (`LOW`, `HIGH`, etc.) | **REMOVED** | Replaced by `decision` (`ALLOW` or `BLOCK`) |
| `indicators` (statistical alarms) | **REMOVED** | Replaced by `matched_rule` and `reason` |
| `ml_result` (anomaly index) | **REMOVED** | Zero ML dependence in core gating |
| `qname` | **Retained** | Normalized to `domain` (lowercased, punycode-decoded) |
| `src_ip` | **Retained** | `client_ip` |
| `qtype` | **Retained** | `qtype` (`A`, `AAAA`, `TXT`, `ANY`, etc.) |
| `timestamp` | **Retained** | `timestamp` (Unix epoch float) |
| *New* | `decision_type` | Explicit policy categorization |
| *New* | `rcode` | Wire RCODE returned to client (`NOERROR`, `REFUSED`, `SERVFAIL`, `FORMERR`) |
| *New* | `response_time_ms` | Precision query round-trip latency |
| *New* | `upstream_server` | Upstream resolver utilized (or `CACHE`) |

---

## 3. Safe Migration Workflow

Historical telemetry is **preserved without modification** in `data/events/dns_events.jsonl`. To migrate historical events into the SQLite database for compliance or reporting:

### Step 1: Run Dry-Run Simulation
Inspect how records will be converted without modifying the database:
```bash
py -3.11 scripts/migrate_legacy_data.py --dry-run
```

### Step 2: Execute Database Ingestion
Migrate records into the SQLite database (`data/dns_gateway.db`):
```bash
py -3.11 scripts/migrate_legacy_data.py --max 5000
```

### Step 3: Verify Integrity in Dashboard
1. Open the SOC dashboard at `http://127.0.0.1:8000/`.
2. Navigate to **DNS Query Logs**.
3. Verify that all historical records display clean **ALLOW** or **BLOCK** badges with explicit reasons, with no lingering risk scores or severity bars.
