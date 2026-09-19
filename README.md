# Agentic Zero-Trust BYOD Firewall

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![OpenSearch](https://img.shields.io/badge/OpenSearch-2.x-blue.svg)
![Ollama](https://img.shields.io/badge/Ollama-llama3.2:1b-black.svg)
![AWS Cedar](https://img.shields.io/badge/Policy-AWS_Cedar-orange.svg)
![iptables](https://img.shields.io/badge/Firewall-iptables-red.svg)

An autonomous, air-gapped, LLM-powered firewall that detects anomalous
network behavior using OpenSearch Random Cut Forest (RCF) machine learning
and dynamically enforces self-healing, time-bound `iptables` bans backed by
AWS Cedar authorization policies.

Built for the **AWS "First Commit" Hackathon (Build It Track)**.

---

## Architecture

The system is organized into four sequential layers.

### Layer 1 — Telemetry & Anomaly Detection
A `scapy` packet sniffer (`ingestion/sniffer.py`) captures live network
traffic and bulk-indexes it every 5 seconds or 50 packets into a local
OpenSearch 2.x cluster (Dockerized single-node). An OpenSearch
Random Cut Forest anomaly detector (`opensearch/rcf_detector.json`) runs
continuous unsupervised learning over the `distinct_dst_ports` cardinality
metric with a 1-minute detection window. When the RCF score exceeds the
anomaly grade threshold, OpenSearch writes an anomaly result record to the
`.opendistro-anomaly-results-history-*` index. This layer does not involve
the LLM at all — the anomaly is flagged entirely by OpenSearch math.

### Layer 2 — Hybrid Reasoning Agent
A Python router (`agent/agent.py`) implements a Hybrid Router Pattern. Low-grade
anomalies (`anomaly_grade < 0.5`) are classified as `BENIGN` and returned
immediately without calling the LLM — this deterministic short-circuit
eliminates inference latency and mode-collapse risk for clear non-events.
High-grade anomalies are passed to `llama3.2:1b` running locally via Ollama.
The LLM's sole responsibility at this stage is to classify the confirmed threat
as `PORT_SCAN` or `BRUTE_FORCE` based on feature data and to draft an AWS Cedar
`forbid` policy. A code-level safety override in Python extracts the real `src_ip`
independently and overwrites any hallucinated IP the model might return.

### Layer 3 — Cedar Policy Sandbox
Before any AI-generated policy is allowed near the kernel, it passes through a
two-stage deterministic sandbox (`policy/validator.py`). Stage 1 compiles the
Cedar string using the official `cedarpy` Rust bindings — any hallucinated
syntax (e.g., `deny ip ... from accessing`) fails here immediately. Stage 2
runs semantic authorization using `cedarpy.is_authorized`: it simulates an
active connection from each protected IP (`127.0.0.1`, `172.27.119.1`) against
the AI's policy. If the Cedar engine returns `Deny` for any critical
infrastructure IP, the policy is rejected before translation even begins.

### Layer 4 — Execution & Self-Healing
Validated Cedar policies are translated by `policy/translator.py` into
`iptables -A INPUT -s <IP> -j DROP` commands. The MCP tool in
`mcp_server/server.py` performs its own independent Cedar validation (it does
not trust the upstream orchestrator), checks for idempotency against the audit
log, and respects a `DRY_RUN` environment variable that defaults to `true`.
`mcp_server/rule_manager.py` records every applied rule to `logs/applied_rules.json`
with a configurable TTL. On expiry, `iptables -D` is called automatically.
On daemon shutdown (`SIGINT`/`SIGTERM`), all remaining active rules are
forcibly reverted before the process exits.

---

## Quick Start (WSL2 / Linux)

### Prerequisites
- Linux or WSL2 (Windows Subsystem for Linux)
- Python 3.11+, Docker Compose, `sudo` privileges
- Ollama installed with `llama3.2:1b` pulled:
  ```bash
  ollama pull llama3.2:1b
  ```

### Setup
```bash
# Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start OpenSearch
docker-compose up -d

# Wait ~30-60s for OpenSearch to become healthy, then initialize
bash opensearch/setup_index.sh
bash opensearch/setup_detector.sh
```

### Running
```bash
# Terminal 1: Packet capture → OpenSearch
bash ingestion/run_sniffer.sh

# Terminal 2: AI + Cedar + iptables enforcement daemon
bash scripts/run_firewall_live.sh

# Terminal 3: Simulate an attack
python scripts/attack_port_scan.py 172.27.112.1
```

Wait approximately 90 seconds for the full pipeline cycle. See
[`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for the exact demo sequence,
timings, and pre-demo checklist.

---

## Known Limitations

These are scoping constraints and observed issues, stated factually.

**WSL2 network capture scope.** The `scapy` sniffer runs inside the WSL2
virtual machine and therefore only sees traffic to and from the WSL2 VM itself
— it does not capture traffic on the host Windows machine's physical Wi-Fi
or Ethernet adapters. This is an expected WSL2 architecture constraint, not
a bug. The system was designed and tested within this scope.

**LLM validation dataset size.** The hybrid agent's LLM half was validated
against a five-scenario hand-written test set (`tests/agent_test_scenarios.json`)
plus the one real OpenSearch anomaly captured during development. This is
sufficient to confirm the pipeline works for the scenarios tested, but it
is explicitly not a large-corpus evaluation. The generalization of the
`PORT_SCAN`/`BRUTE_FORCE` classification to novel traffic patterns has not
been measured. This is a deliberate scoping decision for the hackathon
context.

**Full sniffer-to-daemon live chain.** The individual layers of the pipeline
(ingestion, agent, Cedar sandbox, MCP execution) have each been unit-tested
and integration-tested in isolation. The complete live chain — from physical
packet capture through to a live `iptables` kernel modification triggered by
a real OpenSearch anomaly — should only be considered verified if a human
has run the full 3-terminal demo sequence and observed it succeed. See the
post-demo checklist in `docs/DEMO_GUIDE.md`.

**`cedarpy` entity model.** The semantic authorization sandbox uses an empty
entity store (`entities=[]`). Cedar's full entity model (group hierarchies,
entity attributes) is not used here. The sandbox is sufficient to detect
whether the AI's policy blocks a specific principal, but does not exercise
Cedar's full authorization expressiveness.

---

## Real Engineering Findings

These are things that were directly observed and fixed during development.

**IP hallucination bug.** The `llama3.2:1b` model, when shown a few-shot
example JSON with a hardcoded IP like `192.168.1.105`, would anchor on that
example IP for all `PORT_SCAN` classifications regardless of the actual
payload's `src_ip`. The fix was two-layered: the example IP in the system
prompt was replaced with an obvious `<EXTRACTED_IP_HERE>` placeholder, and
a code-level Python override was added in `agent/agent.py` to independently
extract the real `src_ip` from the payload dict and overwrite the model's
output if they disagree. The LLM is not trusted as the authoritative source
of the IP address.

**Mode collapse under a numeric rubric.** Early attempts to fix the IP issue
by injecting an explicit numerical rubric into the system prompt (e.g.,
"if anomaly_grade < 0.5, classify as BENIGN") caused the 1B-parameter model
to default every payload to `BENIGN` regardless of input — a mode collapse
likely caused by the small model over-fitting to the last seen rule. The fix
was the Hybrid Router Pattern: move all numerical thresholding to deterministic
Python before the LLM call, and simplify the LLM prompt to only handle
confirmed high-grade anomalies.

**Cedar default-deny requires a permit baseline for semantic testing.** When
testing whether the AI's `forbid` policy would block a specific IP, the initial
implementation passed only the `forbid` policy string to `cedarpy.is_authorized`.
Because Cedar uses default-deny, the engine returned `Deny` for every IP
tested — including ones the policy didn't mention — making the semantic
check useless. The fix was to prepend `permit(principal, action, resource);`
as a baseline before the AI's `forbid` policy in the evaluation string. This
correctly models the real system's behavior (default-allow, with AI-authored
forbid overrides) and allows the sandbox to detect specifically which IPs the
AI's policy actively targets.

---

## Live Demo Verification Status

> **This section must be completed by a human after personally running the
> full 3-terminal demo sequence. Do not accept the claims in this section
> as verified unless you have done so yourself.**

```
[ ] Full live chain ran successfully end-to-end
[ ] iptables rule appeared after approximately ___ seconds
[ ] offending_ip in the LLM output matched the real attacker src_ip
[ ] Adversarial sandbox test correctly protected critical infrastructure
[ ] Cleanup script returned iptables to a clean state
[ ] Any issues encountered and resolved: ___________________________
```

---

## License

MIT License. Not intended for production use.
