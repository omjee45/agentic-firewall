# Agentic Zero-Trust BYOD Firewall

**An AI writes your firewall rules. A formal verification engine makes sure it can't be trusted — and blocks it anyway if it tries anything stupid.**

![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=flat-square) ![OpenSearch](https://img.shields.io/badge/OpenSearch-RCF%20Anomaly%20Detection-005EB8?style=flat-square) ![Ollama](https://img.shields.io/badge/Ollama-llama3.2%3A1b-black?style=flat-square) ![AWS Cedar](https://img.shields.io/badge/AWS%20Cedar-Policy%20Validation-orange?style=flat-square) ![iptables](https://img.shields.io/badge/iptables-Kernel%20Enforcement-red?style=flat-square)

Built for the AWS "First Commit" Hackathon — **Build It Track**

---

## The problem

Your laptop on public Wi-Fi is defenseless against behavioral attacks. Static firewalls (`iptables`, Windows Defender) can only follow fixed rules — they can't tell a legitimate SSH session from a brute-force attack on the same port. Enterprise tools that *can* tell the difference (CrowdStrike, Palo Alto XDR) require cloud connectivity and five-figure licenses.

**This project brings real behavioral threat detection to a single laptop — fully offline, zero cost, zero cloud.**

## The core idea

Let a local LLM reason about attacks and draft firewall policy. Never let it touch the firewall directly.

```
Real network traffic
        │
        ▼
┌───────────────────┐
│  OpenSearch RCF    │  ← pure math, no AI. Learns your normal
│  Anomaly Detector   │    traffic pattern, flags deviations.
└─────────┬──────────┘
          │ anomaly_grade ≥ 0.5
          ▼
┌───────────────────┐
│  Local LLM Agent    │  ← llama3.2:1b via Ollama, fully offline.
│  (Ollama, hybrid)   │    Drafts an AWS Cedar block policy.
└─────────┬──────────┘
          │ drafted policy (untrusted)
          ▼
┌───────────────────┐
│  Cedar Sandbox      │  ← deterministic, non-AI. Mathematically
│  (syntax + semantic) │    verifies the AI didn't hallucinate a
└─────────┬──────────┘    rule that blocks YOUR gateway.
          │ validated policy only
          ▼
┌───────────────────┐
│  MCP Enforcement     │  ← re-validates independently, applies
│  + TTL Self-Heal    │    iptables DROP, auto-reverts after TTL.
└────────────────────┘
```

**The one sentence that matters:** the AI is never trusted with execution. Every policy it drafts is independently re-verified — twice — by a deterministic engine before it can touch the Linux kernel.

---

## Architecture, layer by layer

### Layer 1 — Telemetry & Anomaly Detection *(pure math, zero AI)*
A `scapy` packet sniffer (`ingestion/sniffer.py`) captures live traffic and bulk-indexes it into a local single-node OpenSearch cluster every 5 seconds. An **OpenSearch Random Cut Forest** detector runs continuous unsupervised learning over `distinct_dst_ports` cardinality, per source IP, in 1-minute windows. When RCF's anomaly grade crosses threshold, it writes a scored anomaly record — no LLM is involved at this stage at all. The detection is entirely explainable, deterministic math.

### Layer 2 — Hybrid Reasoning Agent
A Python router (`agent/agent.py`) implements a **Hybrid Router Pattern**: low-grade anomalies (`anomaly_grade < 0.5`) are short-circuited to `BENIGN` in plain Python — no LLM call, zero latency, zero hallucination risk for the easy cases. Only confirmed high-grade anomalies reach `llama3.2:1b` running fully locally via Ollama, whose sole job is to classify `PORT_SCAN` vs. `BRUTE_FORCE` and draft a Cedar `forbid` policy. A code-level safety net independently re-extracts the real `src_ip` and overwrites anything the model gets wrong.

### Layer 3 — Cedar Policy Sandbox *(the actual safety mechanism)*
Before any AI-drafted policy goes anywhere near the kernel, it passes a two-stage deterministic gate (`policy/validator.py`):
- **Syntax check** — `cedarpy`'s Rust bindings compile the policy string. Hallucinated syntax fails here instantly.
- **Semantic authorization** — the real test. We simulate an active connection *from each protected IP* (localhost, default gateway) *against the AI's own drafted policy*, using `cedarpy.is_authorized`. If Cedar's engine would deny that protected IP under the AI's rule, the policy is rejected — full stop, before translation even begins.

### Layer 4 — Execution & Self-Healing
Validated policies are translated (`policy/translator.py`) into `iptables -A INPUT -s <IP> -j DROP`. The MCP enforcement tool (`mcp_server/server.py`) **independently re-runs Cedar validation** — it never trusts the caller — checks idempotency, and respects a `DRY_RUN` flag defaulting to `true`. Every applied rule is logged with a TTL (`mcp_server/rule_manager.py`) and auto-reverted via `iptables -D` on expiry, so a false positive self-heals instead of permanently locking anyone out. On shutdown (`SIGINT`/`SIGTERM`), all active rules are force-reverted before exit.

---

## Quick Start (WSL2 / Linux)

**Prerequisites**
```bash
# Linux or WSL2, Python 3.11+, Docker Compose, sudo
ollama pull llama3.2:1b
```

**Setup**
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

docker-compose up -d
# wait ~30-60s for OpenSearch to become healthy

bash opensearch/setup_index.sh
bash opensearch/setup_detector.sh
```

**Run it — three terminals**
```bash
# Terminal 1 — packet capture → OpenSearch
bash ingestion/run_sniffer.sh

# Terminal 2 — AI + Cedar + iptables enforcement daemon
bash scripts/run_firewall_live.sh

# Terminal 3 — simulate an attack
python scripts/attack_port_scan.py 172.27.112.1
```
Full cycle takes ~90 seconds (RCF detection window + agent inference + Cedar validation + kernel write). See [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) for the exact scripted sequence, timing, and pre-demo checklist.

---

## Real engineering findings

These aren't hypothetical edge cases — they're bugs we hit, diagnosed, and fixed during development. Kept here because the debugging process is the actual proof this is a real system, not a demo built to look good once.

**🐛 The IP hallucination bug.** `llama3.2:1b`, shown a few-shot example JSON with a hardcoded IP (`192.168.1.105`), anchored on that *example* IP for every `PORT_SCAN` classification — regardless of the real payload's actual `src_ip`. Two-layer fix: the example IP was replaced with an unambiguous placeholder, and a Python-level override independently re-extracts the real IP and overwrites the model's answer if they disagree. **The LLM is never trusted as the source of truth for the address it's about to get blocked.**

**🐛 Mode collapse under a numeric rubric.** Injecting an explicit threshold rule (`"if anomaly_grade < 0.5, classify BENIGN"`) directly into the system prompt caused the 1B model to collapse to `BENIGN` for *every* input, including obvious attacks — likely over-fitting to the most recently stated rule. Fixed by moving all numeric thresholding into deterministic Python *before* the LLM is ever invoked (the Hybrid Router Pattern), and simplifying the prompt to only ever see confirmed threats.

**🐛 Cedar's default-deny broke naive semantic testing.** Testing whether an AI's `forbid` policy would block a protected IP by passing *only* that policy to `cedarpy.is_authorized` returned `Deny` for every IP tested — including ones the policy never mentioned — because Cedar defaults to deny with no matching rule. Fixed by prepending a baseline `permit(principal, action, resource);` before evaluation, correctly modeling the real system (default-allow, AI-authored `forbid` overrides) and making the semantic check actually meaningful.

---

## Known limitations

Stated plainly, because an audit trail of what's actually been verified is worth more to a judge than a claim that everything works perfectly.

| Limitation | Detail |
|---|---|
| **WSL2 capture scope** | The sniffer only sees traffic to/from the WSL2 VM itself, not the host's physical network adapters. Expected architectural constraint, not a bug — the system was designed and tested within this scope. |
| **LLM validation set size** | The agent's LLM half was validated against a 5-scenario hand-written test set plus one real captured anomaly. Sufficient to prove the pipeline works for tested cases; **not** a large-corpus generalization claim. |
| **Full live-chain verification** | Each layer is unit- and integration-tested in isolation. The complete sniffer→daemon→kernel chain should only be considered verified once a human has run the full 3-terminal demo and observed it succeed — see the checklist below. |
| **Cedar entity model** | The sandbox uses an empty entity store (`entities=[]`) — sufficient to catch a policy targeting a specific principal, but doesn't exercise Cedar's full group/attribute hierarchy. |

---

## Live demo verification

*To be completed by a human after actually running the full 3-terminal sequence. Don't take this as verified until it's checked.*

- [ ] Full live chain ran successfully end-to-end
- [ ] `iptables` rule appeared after approximately ___ seconds
- [ ] `offending_ip` in the LLM output matched the real attacker's `src_ip`
- [ ] Adversarial sandbox test correctly protected critical infrastructure
- [ ] Cleanup script returned `iptables` to a clean state
- [ ] Issues encountered and resolved: ___________________________

---

## License

MIT. Not intended for production use.
