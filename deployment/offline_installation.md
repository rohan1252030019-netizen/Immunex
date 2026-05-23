# IMMUNEX — Offline / Air-Gapped Installation Guide

## Overview

IMMUNEX Layer 4 supports fully offline, air-gapped enterprise deployment.
No internet access is required at runtime. All ML models run locally via
CPU-only execution. The Ollama LLM integration is optional.

---

## Prerequisites

- Python 3.11 or newer
- pip 23.0+
- 8 GB RAM minimum (16 GB recommended)
- 10 GB disk space for models and data

---

## Step 1: Prepare Offline Package on Internet-Connected Machine

### 1a. Download all Python wheels

```bash
# Create a wheels directory
mkdir immunex_wheels

# Download CPU-only PyTorch
pip download torch \
    --index-url https://download.pytorch.org/whl/cpu \
    --dest immunex_wheels \
    --no-deps

# Download all other dependencies
pip download \
    -r requirements.txt \
    --dest immunex_wheels \
    --no-deps

# Verify
ls immunex_wheels/ | wc -l   # Should be 60+ files
```

### 1b. Download Ollama (optional, for LLM playbook generation)

```bash
# Linux
curl -L https://ollama.com/download/ollama-linux-amd64 -o immunex_wheels/ollama

# Windows
# Download manually: https://ollama.com/download/windows
```

### 1c. Pull Ollama model (while online)

```bash
# Start Ollama temporarily
ollama serve &
# Pull the recommended model
ollama pull mistral:7b-instruct-q4_K_M
# Stop Ollama
kill %1

# Locate model files (to transfer offline)
ls ~/.ollama/models/
```

### 1d. Package everything

```bash
zip -r IMMUNEX_OFFLINE_PACKAGE.zip \
    IMMUNEX_COMPLETE/ \
    immunex_wheels/ \
    ~/.ollama/models/
```

---

## Step 2: Install on Air-Gapped Machine

### 2a. Transfer the package

Transfer `IMMUNEX_OFFLINE_PACKAGE.zip` via USB, internal file server,
or secure network transfer.

### 2b. Extract

```bash
unzip IMMUNEX_OFFLINE_PACKAGE.zip -d /opt/immunex
cd /opt/immunex/IMMUNEX_COMPLETE
```

### 2c. Install Python wheels (offline)

```bash
# Install CPU-only PyTorch first
pip install \
    --no-index \
    --find-links /opt/immunex/immunex_wheels \
    torch

# Install all other packages
pip install \
    --no-index \
    --find-links /opt/immunex/immunex_wheels \
    -r requirements.txt
```

### 2d. Install Ollama (optional)

```bash
# Linux
chmod +x /opt/immunex/immunex_wheels/ollama
sudo mv /opt/immunex/immunex_wheels/ollama /usr/local/bin/ollama

# Restore model files
mkdir -p ~/.ollama
cp -r /opt/immunex/models ~/.ollama/

# Verify
ollama list
# Should show: mistral:7b-instruct-q4_K_M
```

---

## Step 3: Verify Installation

```bash
cd /opt/immunex/IMMUNEX_COMPLETE

# Run tests (no internet required)
python -m pytest tests/ -v --timeout=120

# Verify imports
python -c "
from core.adaptive_immunization import AdaptiveImmunizationLayer
from core.mutation_engine import MutationEngine
from core.drift_detector import DriftDetector
from core.defensive_memory import DefensiveMemory
from api.api_server import create_app
print('All Layer 4 modules import successfully')
"
```

---

## Step 4: Launch

### Linux / macOS

```bash
chmod +x deployment/start.sh

# Dashboard only
./deployment/start.sh

# With REST API
./deployment/start.sh --api

# API only (for integration)
./deployment/start.sh --api-only
```

### Windows

```cmd
# Dashboard only
deployment\start.bat

# With REST API
deployment\start.bat --api
```

### Docker (offline)

```bash
# Build image (requires docker, no internet needed after wheel download)
cd /opt/immunex/IMMUNEX_COMPLETE
docker build -f deployment/Dockerfile -t immunex:4.0.0-layer4 .

# Run with docker-compose
docker compose -f deployment/docker-compose.yml up -d

# View logs
docker compose -f deployment/docker-compose.yml logs -f immunex
```

---

## Configuration

All settings are in `config.py`. Key Layer 4 settings:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `layer4.enable_auto_retrain` | `True` | Enable autonomous retraining |
| `layer4.blind_spot_retrain_threshold` | `0.30` | Retrain when blind spot score > 30% |
| `layer4.drift_retrain_threshold` | `0.35` | Retrain when drift score > 35% |
| `layer4.mutation_batch_size` | `100` | Mutations per blind spot test |
| `layer4.memory_retention_days` | `90` | Days to retain threat memory |
| `layer4.api_port` | `8080` | FastAPI server port |

---

## Data Directory Structure

```
data/
├── logs/              # Structured JSON logs (immunex.log)
├── models/            # Trained ML models
│   ├── isolation_forest.joblib
│   └── model_version.json
├── baseline_vectors/  # FAISS index
│   └── faiss_baseline.index
├── memory/            # Persistent threat memory (SQLite)
│   └── threat_memory.db
├── drift/             # Drift analysis reports (JSON)
├── retrain_archive/   # Versioned model backups
└── mutations/         # Mutation generation logs
```

---

## Troubleshooting

**Import errors**: Ensure all wheels installed with `pip install --no-index --find-links`.

**FAISS not found**: Install `faiss-cpu` wheel explicitly (not `faiss-gpu`).

**PyTorch errors**: Use the CPU-only wheel from `download.pytorch.org/whl/cpu`.

**Ollama unavailable**: IMMUNEX continues without Ollama — playbooks generated
using rule-based templates instead of LLM.

**API not reachable**: Check firewall allows port 8080. Use `--api-only` to test
the API without starting the full pipeline.
