# IMMUNEX — Layer 5 Architecture

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    IMMUNEX Autonomous SOC — Full Stack                       │
│                   Layer 5: Enterprise Zero-Trust Operations                  │
│                      (Production-Grade & Air-Gapped)                        │
└─────────────────────────────────────────────────────────────────────────────┘

                          ┌─────────────────┐
                          │  SIEM/EDR Feed  │
                          │  StreamEngine   │
                          └────────┬────────┘
                                   │ SecurityEvent
                          ┌────────▼────────┐
                          │  FeaturePipeline │ ← Normalization
                          └────────┬────────┘
                                   │ FeatureVector (10-dim float32)
               ┌───────────────────┼───────────────────┐
               │                   │                   │
    ┌──────────▼─────────┐ ┌───────▼────────┐         │
    │  IsolationForest    │ │ FAISS VectorDB │         │
    │  AnomalyEngine      │ │ VectorEngine   │         │
    └──────────┬──────────┘ └───────┬────────┘         │
               │                   │                   │
               └──────────┬────────┘                   │
                          │ DetectionDecision           │
                 ┌────────▼─────────┐                  │
                 │   LAYER 1         │◄─────────────────┘
                 │  InnateImmunity  │  Drift ingest
                 └────────┬─────────┘
                          │ (anomaly detected)
                 ┌────────▼─────────────────────┐
                 │   LAYER 2                    │
                 │  AdaptiveIntelligence        │
                 │  ┌─────────────────────────┐  │
                 │  │ GraphEngine             │  │
                 │  │ CorrelationEngine       │  │
                 │  │ MarkovPredictor         │  │
                 │  │ NarrativeEngine         │  │
                 │  └─────────────────────────┘  │
                 └────────┬─────────────────────-┘
                          │ ThreatReport (campaign)
                 ┌────────▼─────────────────────┐
                 │   LAYER 3                    │
                 │  ImmuneResponse              │
                 │  ┌─────────────────────────┐  │
                 │  │ RLDecisionEngine        │  │
                 │  │ PolicyEngine            │  │
                 │  │ PlaybookEngine          │  │
                 │  │ OllamaOrchestrator      │  │
                 │  └─────────────────────────┘  │
                 └────────┬─────────────────────-┘
                          │ ImmunityResponse
                 ┌────────▼─────────────────────┐
                 │   LAYER 4                    │
                 │  AdaptiveImmunization        │
                 │  ┌─────────────────────────┐  │
                 │  │ DefensiveMemory         │  │ ← SQLite persistence
                 │  │ MutationEngine          │  │ ← Synthetic zero-days
                 │  │ ValidationEngine        │  │ ← Blind spot analysis
                 │  │ DriftDetector           │  │ ← PSI/KL monitoring
                 │  │ RetrainingPipeline      │  │ ← Auto model update
                 │  │ SchedulerEngine         │  │ ← Background tasks
                 │  └─────────────────────────┘  │
                 └────────┬─────────────────────-┘
                          │ Layer4Event
                 ┌────────▼─────────────────────┐
                 │   LAYER 5 ★ NEW               │
                 │  Enterprise Zero-Trust SOC   │
                 │  ┌─────────────────────────┐  │
                 │  │ Zero-Trust RBAC         │  │ ← Token-based auth
                 │  │ Cryptographic Ledger     │  │ ← SHA-256 chain verification
                 │  │ DistributedAgentCache   │  │ ← Heartbeat & registry
                 │  │ ReportingEngine (PDF)   │  │ ← SOC2, NIST, ISO mapping
                 │  │ DashboardAnalytics      │  │ ← Dynamic KPI & Hotspots
                 │  └─────────────────────────┘  │
                 └────────┬─────────────────────-┘
                          │ Layer5Event
                 ┌────────▼─────────────────────┐
                 │     FastAPI REST Gateway     │
                 │  /auth/login /soc/cases/note │
                 │  /audit/ledger/verify        │
                 │  /agents/heartbeat/register  │
                 │  /reports/pdf/compliance     │
                 │  /analytics/heatmap/kpi      │
                 └──────────────────────────────┘
```

---

## Layer 5 Components

### Zero-Trust RBAC Enforcer (`auth/` & `api/routes.py`)
Provides strict, token-based Role-Based Access Control (RBAC). Validates all incoming API operations against JWT payloads.

**Predefined Enterprise Roles:**
* `admin`: Complete administrative permissions. Can trigger manual model retraining, overwrite policies, register endpoints, and clear logs.
* `analyst`: SOC research permissions. Can view live timelines, create analyst case notes, export reports, and read correlation graphs.
* `responder`: Active incident containment permissions. Can trigger playbook actions, edit mitigation policies, and update incident statuses.
* `auditor`: Compliance verification permissions. Can read cryptographic audit ledgers, verify ledger block integrity, and export compliance reports.

---

### Cryptographic Audit Pipeline (`audit/`)
A tamper-proof ledger running SHA-256 block hashing over every corporate security event, status transition, playbook execution, and configuration change. 

**Integrity Verification:**
* Each audit record links to the previous block's SHA-256 hash forming a secure, unbroken cryptographic ledger.
* Any external database modification instantly breaks the chain validation, triggering high-severity SOC indicators.

---

### Distributed Telemetry Cache (`agents/`)
Monitors and manages distributed agent endpoints across corporate assets. Tracks registrations, heartbeat statuses, and live health statistics to maintain total environment visibility.

---

### Executive & Compliance Reporting (`reporting/`)
Pure offline, high-quality documentation suite mapping active incident indicators to key industry regulatory frameworks.

* **ReportLab PDF Exporter (`pdf_report_generator.py`)**: High-quality document layout generation with compliance score matrices and visual forensics.
* **Compliance Auditor (`compliance_reporter.py`)**: Automatic mapping to:
  - **SOC 2 Type II**: CC6.1 (Boundary protection), CC7.2 (Anomaly identification), CC7.3 (Vulnerability resolution).
  - **NIST SP 800-53 Rev 5**: SI-4 (Information System Monitoring), IR-4 (Incident Handling), CM-2 (Baseline Configuration).
  - **ISO/IEC 27001:2022**: A.8.16 (Monitoring activities), A.8.20 (Network security), A.8.24 (Use of cryptography).

---

### Real-Time Analytics Dashboard (`dashboard/`)
Consolidates pipeline stats to feed real-time interfaces without database polling.
* **Alert Heatmap (`HeatmapEngine`)**: Geospatial and network-level heatmaps highlighting correlation clusters.
* **Live KPI Feed (`RealtimeDashboard`)**: Computes mean time to detect (MTTD), mean time to mitigate (MTTM), and overall zero-trust compliance posture metrics.

---

## FastAPI Route Specifications

| Method | Path | Required Role | Description |
|--------|------|---------------|-------------|
| POST | `/api/v5/auth/login` | *Public* | Authenticates users and issues JWT access tokens. |
| GET | `/api/v5/soc/cases` | `analyst`, `admin` | Fetches active incidents and open analyst cases. |
| POST | `/api/v5/soc/cases/{case_id}/note` | `analyst` | Adds collaborative analysis notes to an active case. |
| POST | `/api/v5/soc/cases/{case_id}/status` | `responder`, `admin` | Transitions case lifecycle statuses. |
| POST | `/api/v5/agents/register` | `admin` | Enrolls a new distributed endpoint agent. |
| POST | `/api/v5/agents/heartbeat` | *Agent* | Updates endpoint telemetry and tracks agent heartbeats. |
| GET | `/api/v5/agents/status` | `analyst`, `admin` | Retrieves live agent health grid. |
| GET | `/api/v5/audit/ledger` | `auditor`, `admin` | Returns the absolute audit trail log. |
| POST | `/api/v5/audit/ledger/verify` | `auditor`, `admin` | Validates SHA-256 hash chains across the entire ledger. |
| GET | `/api/v5/analytics/kpis` | `analyst`, `admin` | Serves real-time SOC metrics (MTTD, MTTM, Compliance). |
| GET | `/api/v5/analytics/heatmap` | `analyst`, `admin` | Generates active campaign density heatmaps. |
| GET | `/api/v5/reports/pdf/{incident_id}` | `analyst`, `admin`, `auditor` | Generates and exports executive forensic PDF report. |
| GET | `/api/v5/reports/compliance` | `auditor`, `admin` | Compiles detailed framework mapping report (PDF/Markdown). |
| GET | `/api/v5/reports/stix/{incident_id}` | `analyst`, `admin` | Exports threat data as valid STIX 2.1 Bundles. |us background task scheduler using APScheduler (or asyncio fallback).

| Task | Default Interval | Purpose |
|------|-----------------|---------|
| Drift analysis | 5 minutes | PSI monitoring |
| Mutation test | 10 minutes | Blind spot probing |
| Health check | 1 minute | System metrics |
| Memory cleanup | 24 hours | Remove old entries |
| Metrics aggregation | 30 seconds | Observability |
| Scheduled retrain | 1 hour | Proactive maintenance |

---

## FastAPI Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | System health status |
| GET | `/stream` | Stream throughput statistics |
| GET | `/alerts` | Recent alert summaries |
| GET | `/graph` | Attack graph topology |
| POST | `/playbook` | Generate incident playbook |
| GET | `/mitigation` | Recent mitigation decisions |
| POST | `/retrain` | Trigger model retraining |
| GET | `/metrics` | Observability metrics |
| GET | `/threat-memory` | Memory stats + recent entries |
| POST | `/threat-memory/correlate` | Correlate incident vs history |

Interactive docs: `http://localhost:8080/docs`

---

## Data Flow: Autonomous Retraining

```
[Drift detected / Blind spots found]
           │
           ▼
[Pre-Validation: run 100 mutations → measure blind_spot_score]
           │
           ▼
[Archive: copy models to data/retrain_archive/RTN-NNNN_timestamp/]
           │
           ▼
[Build augmented training data]
   Normal traffic: 1000 synthetic samples
   Attack mutations: 200 generated variants
           │
           ▼
[Retrain IsolationForest on 1200 combined samples]
           │
           ▼
[Recalibrate threshold: sweep percentiles, minimise FP+FN]
           │
           ▼
[Rebuild FAISS index from 1000 normal-only samples]
           │
           ▼
[Post-Validation: run 100 mutations → measure new blind_spot_score]
           │
    ┌──────┴──────┐
    │             │
[Improved?]   [Regressed?]
    │             │
  [Deploy]    [Rollback]
    │             │
[Version tag] [Restore archive]
```
