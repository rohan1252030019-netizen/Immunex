# IMMUNEX — Autonomous SOC · Layer 5: Enterprise Zero-Trust Operations

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![CPU-Only](https://img.shields.io/badge/compute-CPU--only-green.svg)]()
[![Air-Gapped](https://img.shields.io/badge/deployment-air--gapped-orange.svg)]()
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg)](https://fastapi.tiangolo.com)

IMMUNEX is an enterprise-grade, fully autonomous cyber-defense platform that detects, analyses, responds to, and adapts against advanced threats — entirely offline, CPU-only, with zero cloud dependencies.

---

## Architecture

```
Stream → Normalize → IsolationForest → FAISS → Graph Correlation
  → Attack Reconstruction → Threat Prediction → Narrative Generation
    → RL Mitigation → Policy Verification → Ollama Playbook
      → Threat Memory → Mutation Testing → Blind Spot Analysis
        → Drift Detection → Automated Retraining → Redeployment
          → Zero-Trust RBAC Enforcer → Cryptographic Audit Logs → ReportLab Executive PDFs
```

### Layers

| Layer | Module | Responsibility |
|-------|--------|----------------|
| 1 | `InnateImmunityLayer` | IsolationForest + FAISS detection |
| 2 | `AdaptiveIntelligenceLayer` | Graph correlation, Markov prediction |
| 3 | `ImmuneResponseEngine` | RL mitigation, policy, Ollama playbooks |
| 4 | `AdaptiveImmunizationLayer` | Self-evolving: memory, mutation, drift, retrain |
| **5** | **`EnterpriseSOCOperations`** | **Enterprise: Zero-Trust RBAC, Cryptographic Ledger, Distributed Agents, Reports** |

---

## Layer 5: What's New

### Zero-Trust Access Control & RBAC (`auth/` & `api/routes.py`)
Provides strict, token-based Role-Based Access Control (RBAC). Validates all incoming API operations against JWT payloads. Predefined roles include `ADMINISTRATOR`, `SOC_ANALYST`, `INCIDENT_RESPONDER`, and `AUDITOR` to guarantee least-privilege security.

### Cryptographic Audit Ledger (`audit/`)
A tamper-proof ledger running SHA-256 block hashing over every corporate security event, status transition, playbook execution, and configuration change. Each audit record links to the previous block's SHA-256 hash forming a secure, unbroken cryptographic ledger.

### Distributed Telemetry Cache (`agents/`)
Monitors and manages distributed agent endpoints across corporate assets. Tracks registrations, heartbeat statuses, and live health statistics to maintain total environment visibility.

### Executive & Compliance Reporting (`reporting/`)
Pure offline, high-quality documentation suite mapping active incident indicators to key industry regulatory frameworks:
* **ReportLab PDF Exporter (`pdf_report_generator.py`)**: High-quality document layout generation with compliance score matrices and visual forensics.
* **Compliance Auditor (`compliance_reporter.py`)**: Automatic mapping to SOC 2 Type II (Boundary Protection & Vulnerability Resolution), NIST SP 800-53 Rev 5 (Information System Monitoring & Incident Handling), and ISO/IEC 27001:2022 (Monitoring activities & Use of cryptography).
* **Forensic Timeline Exporter (`timeline_reporter.py`)**: Computes chronological event streams for court-admissible forensic audit paths.
* **Incident Exporter (`incident_exporter.py`)**: Generates valid, structured JSON and STIX 2.1 Threat Intelligence Bundles.

### Real-Time Dashboard Analytics (`dashboard/`)
Consolidates pipeline stats to feed real-time interfaces without database polling.
* **Alert Heatmap (`HeatmapEngine`)**: Geospatial and network-level heatmaps highlighting correlation clusters.
* **Live KPI Feed (`RealtimeDashboard`)**: Computes mean time to detect (MTTD), mean time to mitigate (MTTM), and overall zero-trust compliance posture metrics.

---

## Quick Start

### Requirements
- Python 3.11+
- 8 GB RAM
- No GPU required

### Install

```bash
# CPU-only PyTorch (required first)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# All other dependencies
pip install -r requirements.txt
```

### Run

```bash
# Dashboard mode (terminal)
python main.py

# Pipeline + REST API
python main.py --api

# REST API only (for integration)
python main.py --api-only
```

### Docker

```bash
cd deployment
docker compose up -d

# View logs
docker compose logs -f immunex

# Stop
docker compose down
```

---

## Pre-configured Enterprise Credentials

For testing and demonstration, use the following local corporate identities:

| Username | Role | Secret Password |
|----------|------|-----------------|
| `admin` | `ADMINISTRATOR` | `administrator_secret_soc` |
| `analyst` | `SOC_ANALYST` | `analyst_secret_soc` |
| `responder` | `INCIDENT_RESPONDER` | `responder_secret_soc` |
| `auditor` | `AUDITOR` | `auditor_secret_soc` |

---

## REST API Gateway

Interactive API docs available at: `http://localhost:8080/docs`

### Key Endpoints

#### 1. Authentication
```bash
# Get dynamic JWT access token
curl -X POST http://localhost:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "administrator_secret_soc"}'
```

#### 2. SOC Case Management
```bash
# Fetch active incidents (Requires Authorization: Bearer JWT)
curl http://localhost:8080/soc/cases \
     -H "Authorization: Bearer <TOKEN>"

# Append analyst notes to a case
curl -X POST http://localhost:8080/soc/cases/CAM-001/notes \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"note": "Investigating lateral movement patterns on TIER-1 assets."}'
```

#### 3. Cryptographic Auditing
```bash
# Fetch audit ledger events
curl http://localhost:8080/audit/logs \
     -H "Authorization: Bearer <TOKEN>"
```

#### 4. Executive Reporting
```bash
# Generate dynamic executive ReportLab PDF
curl -X POST http://localhost:8080/reports/generate \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"report_type": "incident", "format": "pdf", "campaign_id": "CAM-001"}'
```

---

## Offline / Air-Gapped Deployment

See `deployment/offline_installation.md` for the complete guide.

No internet access is required at runtime. All inference and report compiling is performed locally.

---

## Configuration

Edit `config.py` to tune Layer 5 behavior:

```python
Layer5Config(
    enable_jwt_auth=True,
    jwt_secret="local_enterprise_key_for_zero_trust_immunex",
    token_expiry_minutes=60,
    persistent_reports_dir="data/reports",
)
```

---

## Verification & Tests

```bash
# Run the complete test suite (all 25+ files)
python -m pytest tests/ -v

# Run Layer 5 specific integration tests
python -m pytest tests/test_soc_pipeline.py tests/test_rbac.py tests/test_audit_pipeline.py tests/test_reporting.py -v
```

---

## Project Structure

```
IMMUNEX_COMPLETE/
├── main.py                          # Entry point (all modes)
├── config.py                        # All configuration
├── requirements.txt
├── core/
│   ├── innate_immunity.py           # Layer 1 orchestrator
│   ├── anomaly_engine.py            # IsolationForest
│   ├── vector_engine.py             # FAISS
│   ├── feature_pipeline.py          # Normalisation
│   ├── stream_engine.py             # Async SIEM/EDR stream
│   ├── adaptive_intelligence.py     # Layer 2 orchestrator
│   ├── graph_engine.py              # Attack graph
│   ├── correlation_engine.py        # Campaign correlation
│   ├── markov_predictor.py          # HMM prediction
│   ├── narrative_engine.py          # Report generation
│   ├── immune_response.py           # Layer 3 orchestrator
│   ├── rl_decision_engine.py        # RL mitigation
│   ├── policy_engine.py             # Safety constraints
│   ├── playbook_engine.py           # Incident playbooks
│   ├── ollama_orchestrator.py       # Local LLM
│   ├── mitigation_actions.py        # Platform commands
│   ├── response_models.py           # Layer 3 data models
│   ├── adaptive_immunization.py     # Layer 4 orchestrator
│   ├── mutation_engine.py           # Synthetic zero-days
│   ├── drift_detector.py            # PSI drift monitoring
│   ├── validation_engine.py         # Blind spot analysis
│   ├── retraining_pipeline.py       # Auto model update
│   ├── defensive_memory.py          # Threat memory (SQLite)
│   └── scheduler_engine.py          # Background tasks
├── auth/                            # ★ Layer 5 Security
│   ├── jwt_manager.py               # Token issuer & validator
│   ├── rbac_engine.py               # Role & permission map
│   ├── auth_middleware.py           # Dependency-injected guard
│   └── access_policy_engine.py      # Zero-Trust network rules
├── audit/                           # ★ Layer 5 Ledger
│   ├── immutable_event_store.py     # SHA-256 Blockchain log
│   └── compliance_engine.py         # SOC2/NIST/ISO mapping
├── agents/                          # ★ Layer 5 Telemetry
│   └── agent_state_cache.py         # Distributed agents registrar
├── dashboard/                       # ★ Layer 5 Dashboard
│   ├── realtime_dashboard.py        # Live metrics / KPI cache
│   └── heatmap_engine.py            # MITRE tactic densities
├── reporting/                       # ★ Layer 5 Executive Reports
│   ├── pdf_report_generator.py      # ReportLab PDF engine
│   ├── markdown_report_generator.py # Forensics markdown builder
│   ├── compliance_reporter.py       # Mapping compiler
│   ├── incident_exporter.py         # STIX 2.1 exporter
│   └── timeline_reporter.py         # Chronological forensic streams
├── api/
│   ├── api_server.py                # FastAPI application
│   ├── routes.py                    # Upgraded routes with auth & audits
│   ├── models.py                    # Upgraded schemas
│   └── middleware.py                # Logging, timing, rate limit
├── deployment/
│   ├── Dockerfile                   # Production container
│   ├── docker-compose.yml           # Full stack deployment
│   ├── start.sh                     # Linux/macOS startup
│   ├── start.bat                    # Windows startup
│   ├── offline_installation.md      # Air-gapped guide
│   └── architecture.md              # Architecture docs
├── tests/                           # Complete test suite
│   ├── test_anomaly.py
│   ├── test_vector_engine.py
│   ├── test_correlation.py
│   ├── test_graph_engine.py
│   ├── test_markov.py
│   ├── test_mitigation_pipeline.py
│   ├── test_playbook_engine.py
│   ├── test_policy_engine.py
│   ├── test_rl_engine.py
│   ├── test_stream.py
│   ├── test_mutation_engine.py
│   ├── test_drift_detection.py
│   ├── test_retraining.py
│   ├── test_api.py
│   ├── test_full_pipeline.py
│   ├── test_soc_pipeline.py        # ★ Layer 5 SOC pipeline
│   ├── test_ioc_engine.py          # ★ Layer 5 Threat intel
│   ├── test_analytics.py           # ★ Layer 5 Mitre heatmaps
│   ├── test_rbac.py                # ★ Layer 5 Access policies
│   ├── test_agents.py              # ★ Layer 5 Distributed agents
│   ├── test_audit_pipeline.py      # ★ Layer 5 Blockchain ledger
│   ├── test_dashboard.py           # ★ Layer 5 Dashboard KPIs
│   ├── test_reporting.py           # ★ Layer 5 Report generators
│   └── test_distributed_pipeline.py# ★ Layer 5 End-to-end telemetry
└── data/
    ├── logs/
    ├── models/
    ├── baseline_vectors/
    ├── memory/                      # Threat memory (SQLite)
    ├── drift/                       # Drift reports
    ├── retrain_archive/             # Model version history
    └── reports/                     # ★ Compiled executive PDF/MDs
```

★ = Upgraded / Added in Layer 5

---

## License

Enterprise internal use. All rights reserved.
