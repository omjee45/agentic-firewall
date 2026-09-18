# Agentic Zero-Trust BYOD Firewall

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-llama3.2:1b-black.svg)
![AWS Cedar](https://img.shields.io/badge/Policy-AWS_Cedar-orange.svg)
![iptables](https://img.shields.io/badge/Firewall-iptables-red.svg)

An autonomous, air-gapped, LLM-powered firewall that detects zero-day network anomalies via OpenSearch Random Cut Forests (RCF) and dynamically enforces self-healing, time-bound `iptables` bans using AWS Cedar authorization.

Built for the **AWS "First Commit" Hackathon (Build It Track)**.

---

## 🏗 Architecture & Data Flow

This firewall implements a **Hybrid Router Pattern** with strict **Deterministic Sandboxing** and **Defense-in-Depth**.

1. **Ingestion & Telemetry:** A `scapy` packet sniffer captures live traffic and bulk-indexes it into a local OpenSearch cluster.
2. **Anomaly Detection:** An OpenSearch RCF (Random Cut Forest) anomaly detector runs continuous unsupervised machine learning against the traffic to detect port scans and brute-force patterns.
3. **Hybrid Agent Router:** When an anomaly is detected, deterministic Python code intercepts low-confidence (Benign) traffic instantly. High-confidence anomalies are passed to a local `llama3.2:1b` (via Ollama) to draft an AWS Cedar `forbid` policy.
4. **Cedar Sandbox:** Before any AI policy touches the kernel, it is compiled by the official `cedarpy` Rust bindings. We then simulate connections from critical infrastructure (like `127.0.0.1`) through the AWS Cedar Authorization Engine. If the AI hallucinates a policy that blocks the gateway, it is instantly rejected.
5. **Enforcement & Self-Healing:** Validated policies are translated by an MCP tool into live `iptables -A DROP` rules. A local state manager tracks Time-to-Live (TTL) and automatically reverts (`iptables -D`) the rule when it expires.

## 🚀 Quick Start (Localhost / WSL2)

### 1. Prerequisites
* **OS:** Linux or WSL2 (Windows Subsystem for Linux)
* **Dependencies:** Python 3.11+, Docker Compose, `iptables`, `sudo` privileges.
* **Ollama:** Installed locally and serving the `llama3.2:1b` model (`ollama pull llama3.2:1b`).

### 2. Setup
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/agentic-firewall.git
cd agentic-firewall

# Setup Virtual Environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start OpenSearch & OpenSearch Dashboards
docker-compose up -d
```

### 3. Initialize OpenSearch
Wait for OpenSearch to become healthy (usually ~30-60 seconds), then configure the schema and the RCF detector:
```bash
bash opensearch/setup_index.sh
bash opensearch/setup_detector.sh
```

### 4. Run the Pipeline
The system operates via two background daemons.

**Terminal 1: Start the Sniffer**
```bash
# Captures live traffic on the host interface and feeds OpenSearch
sudo $(which python3) ingestion/sniffer.py
```

**Terminal 2: Start the Agentic Enforcer Daemon**
```bash
# Polls OpenSearch for anomalies, evaluates them via Llama 3, and modifies iptables
# (Dry-run mode is ON by default for safety)
sudo $(which python3) agent/enforcer_daemon.py
```

### 5. Simulate an Attack
While the daemons are running, use the built-in attack simulators to trigger the AI:
```bash
# Simulate a Port Scan
python scripts/attack_port_scan.py 198.51.100.55

# Simulate a Brute Force Attack
python scripts/attack_brute_force.py 198.51.100.56
```
Watch the Enforcer Daemon terminal! You will see the AI intercept the anomaly, generate the Cedar policy, pass the sandbox validation, and safely drop the mock IP.

---

## 🔒 Safety & Constraints
* **100% Air-Gapped:** The entire stack (OpenSearch, LLM, Firewall) runs locally. Zero cloud bills, zero external API calls.
* **Dry Run Default:** The enforcer strictly defaults to `DRY_RUN=true`. It will not modify your host's iptables unless you explicitly export `DRY_RUN=false`.
* **Graceful Exit:** If the Live Daemon is killed (`Ctrl+C`), it aggressively reverts all active `iptables` bans it created before shutting down.

## 📜 License
MIT License. Not intended for production use.
