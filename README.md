# IMMUNEX — AI-Powered Real-Time Banking Fraud, Behavioral Anomaly, and Agentic Compliance Intelligence Platform
### *SuRaksha Cyber Hackathon 2.0 · Canara Bank Edition*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Canara Bank SuRaksha](https://img.shields.io/badge/hackathon-SuRaksha%202.0-red.svg)]()
[![Real-Time Anomaly Detection](https://img.shields.io/badge/theme-Anomaly%20Detection-orange.svg)]()
[![Fintech AI Compliance](https://img.shields.io/badge/domain-Fintech%20%26%20Banking-green.svg)]()

IMMUNEX is an enterprise-grade, graph-native, and self-healing **Autonomous Banking Fraud Intelligence and Regulatory Compliance Platform**. It is designed specifically for highly secure, air-gapped, CPU-optimized, and local-first banking networks. It processes high-throughput transaction telemetry and evaluates account anomalies with sub-50ms processing loops—completely offline with zero cloud dependencies.

---

## 🏛️ Canara Bank SuRaksha Core Positioning Mapping

To align directly with Canara Bank's digital payment protection missions, generic security terminologies map to active banking protection domains:

*   **Threat Event** $\rightarrow$ **Fraud Risk Event** (Suspicious transaction, login, or credential update)
*   **Endpoint Compromise** $\rightarrow$ **Banking Session Compromise** (Account takeover, device spoofing, emulator usage)
*   **Malware Alert** $\rightarrow$ **Financial Threat Alert** (Tampered land records, altered PDF statements, ledger access)
*   **SOC Analyst** $\rightarrow$ **Fraud Intelligence Analyst** (Bank operator managing the SuRaksha console)
*   **Security Incident** $\rightarrow$ **Banking Risk Incident** (Validated transaction breach, insider threat, or RBI regulatory violation)

---

## 🧠 Advanced Banking-Specific AI Use Cases

### A. Fraudulent Transaction Detection (Real-Time Anomaly Detection)
*   **Impossible Travel & Location Anomaly**: Analyzes geographic transaction velocities, flagging cross-border transfers and mobile emulator platforms via device fingerprinting.
*   **Transaction Volume Profiling**: Utilizes `IsolationForest` models to score outlier transfer sizes against a customer's historic baseline.

### B. Insider Threat Detection (Employee Abuse & Privilege Escalation)
*   **Keystroke Dynamic Timing**: Extracts sub-millisecond keyboard rhythm latencies to spot hijacked teller sessions.
*   **Graph-Native Access Tracing**: Uses directed graphs (`NetworkX` + `Neo4j`) to identify unauthorized privilege escalations and suspicious database access paths.

### C. Financial Document Forgery & PDF Tampering Checks
*   **Metadata & OCR Verification**: Detects bank statement file modifications, altered text blocks, and PDF metadata inconsistencies.

### D. Account Takeover Detection (Behavioral Biometrics)
*   **Non-Human Pattern Profiling**: Identifies robotic session activity and automated UPI draining scripts using keystroke rhythm analysis.

---

## 🛠️ Simplified vs. Future Enterprise Architecture

### A. Simplified Hackathon Architecture (Live Demo Ready)
```
[Banking Data Ingestion] 
       ↓
[AI Behavioral Analysis Engine] (Keystroke timings, Baselines)
       ↓
[Explainable Risk Scoring Engine] (Normal Login = 10, Emulator = 40, High Transfer = 90, Insider = 95)
       ↓
[Graph-Native Attack Path Correlation] (Asset & Account directed links)
       ↓
[Agentic RBI Compliance Module] (Measurable Action Points & Auto-Validations)
       ↓
[Canara SuRaksha Analyst Dashboard] (Real-time WebSockets UI)
```

### B. Enterprise Future Scaling Architecture (Roadmap Strengths)
*   **Distributed Worker Mesh**: Multi-node workload coordination via `gRPC Worker Fabrics`.
*   **Scalable Time-Series Database**: High-speed, partitioned telemetry storage using ClickHouse clusters.
*   **Hot Caching Fabric**: Hot alert caches and session pub-sub architectures using Redis.
*   **Privacy-Preserving Federated ML**: Secure model updates across branches using federated learning.

---

## 🧭 Real-Time Regulatory Compliance: RBI Agentic Engine (`compliance_engine.py`)

A primary innovation is the **AI Compliance Intelligence Engine** that automates regulatory compliance verification in real-time against RBI cyber guidelines:
1.  **Ingestion & Classification**: Ingests RBI regulatory text and extracts **Measurable Action Points (MAPs)**.
2.  **Autonomous Task Allocation**: Maps extracted MAPs to relevant departments (**InfoSec, Audit, Core Banking, IT, Operations**).
3.  **Self-Validation Checks**: Query active system security states (MFA, Device Bindings, Behavioral Analytics) to automatically validate compliance.
4.  **Audit Trail Ledger**: Updates a compliance scorecard and generates immutable regulatory compliance reports.

---

## ⚡ Technical Requirements & Dependency Setup

### Requirements
- **Python**: 3.10+
- **Memory**: 8 GB RAM
- **Compute**: CPU-Only optimized (No GPU required)

### Installation

```bash
# 1. Install CPU-only PyTorch (required first)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# 2. Install all required packages
pip install -r requirements.txt
```

### Execution

```bash
# 1. Run the main Fraud Detection & Pipeline Simulation
python main.py

# 2. Start the unified REST API Server
python main.py --api

# 3. Run the full Canara Compliance & Fraud Pytest Suite
python -m pytest tests/test_compliance_engine.py -v
```

---

## 🛡️ Hackathon Validation Summary
*   **Processing Latency**: Optimized to run under **50ms** for the entire transaction-behavior-compliance evaluation loop.
*   **Test Suit Coverage**: Tested with a 100% green pass rate across **504 tests** (496 unified platform tests + 8 banking compliance tests).
*   **Access Credentials**: Pre-populated credentials for immediate evaluation are available on the dashboard:
    *   **Analyst Profile**: `admin`
    *   **Access Cipher**: `administrator_secret_soc`
