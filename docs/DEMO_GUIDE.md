# Demo Guide — Agentic Zero-Trust Firewall

This is the exact terminal sequence for a live demonstration. Follow it
literally. Do not improvise timing — the RCF detector needs real time to
accumulate enough data before it will flag an anomaly.

---

## Pre-Demo Checklist (run these before opening any presentation)

Run each command and confirm the expected output before proceeding.

```bash
# 1. Wipe any leftover firewall state from previous runs
sudo bash scripts/cleanup.sh --hard
```
**Expected:** "Cleanup complete." No errors. iptables INPUT chain is empty.

```bash
# 2. Confirm iptables INPUT is actually empty
sudo iptables -L INPUT -n -v
```
**Expected:** Zero rules listed in the INPUT chain.

```bash
# 3. Confirm Ollama model is loaded and available
ollama list
```
**Expected:** `llama3.2:1b` appears in the list.

```bash
# 4. Confirm OpenSearch is up and the RCF detector is RUNNING
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
curl -s -X POST "http://localhost:9200/_plugins/_anomaly_detection/detectors/ZY7AtKABEHSa55H-Iqxw/_profile/init_progress" | python3 -m json.tool
```
**Expected:** Cluster status `green` or `yellow` (not `red`). Detector
returns state `RUNNING`. If it shows `INIT`, wait 2 minutes and re-check
before starting the demo — the RCF model needs a data baseline.

---

## Live Demo Sequence

Open **three terminals** side by side. All terminals must be inside
the project directory (`cd /mnt/d/agentic-firewall` on WSL2).

---

### Terminal 1 — Packet Sniffer

```bash
bash ingestion/run_sniffer.sh
```

Wait until you see lines like:
```
Indexed X packets. Failed: 0
```
This confirms live traffic is being captured and bulk-indexed into
OpenSearch. Leave this running for the entire demo.

---

### Terminal 2 — Live Firewall Daemon

```bash
bash scripts/run_firewall_live.sh
```

This starts `agent/enforcer_daemon.py` with `DRY_RUN=false` under sudo.
You will see:
```
AGENTIC ZERO-TRUST FIREWALL DAEMON INITIALIZED
[DAEMON] Starting polling loop (interval: 10s)
```
Leave this running. It polls OpenSearch every 10 seconds and will react
automatically when the RCF detector flags an anomaly.

---

### Terminal 3 — Attack Simulation & Adversarial Test

**Step A: Trigger a port scan**
```bash
python scripts/attack_port_scan.py 172.27.112.1
```

**⚠️ Wait approximately 90 seconds after the scan completes.**

> Do not rush this step. The RCF anomaly detector operates on a 1-minute
> window with a 1-minute delay. The detection event must be written to
> OpenSearch, the daemon must poll and find it, the LLM must reason over
> it, the Cedar sandbox must validate the policy, and only then does
> iptables get modified. This pipeline takes 60–120 seconds in practice.
> Watch Terminal 2 for the `[DAEMON] >> NEW Anomaly Payload Detected` line.

**Step B: Confirm the iptables rule was applied**
```bash
sudo iptables -L INPUT -n -v
```
**Expected:** A DROP rule for the attacker's IP (`172.27.119.29` or
whichever IP generated the scan) appears in the INPUT chain.

**Step C: Run the adversarial test**

This proves the Cedar sandbox blocks the LLM from writing a policy that
would ban critical infrastructure (the WSL gateway itself):
```bash
python tests/test_sandbox_adversarial.py
```
**Expected:** Tests 2 and 3 print `PASS (Successfully Intercepted)`.
The gateway IP is never inserted into iptables.

**Step D: Trigger TTL expiration / cleanup**
```bash
sudo bash scripts/cleanup.sh
```
**Expected:** The DROP rule is removed. iptables INPUT chain returns to
empty. The daemon in Terminal 2 also auto-reverts rules when their
300-second TTL expires naturally.

---

## Post-Demo Notes

After presenting, update the section below with what you observed:

```
[ ] Full 3-terminal live chain ran successfully on first attempt
[ ] iptables rule appeared after ~__ seconds (actual timing: ___)
[ ] offending_ip in the LLM response matched the real attacker IP
[ ] Adversarial test correctly intercepted the gateway-blocking policy
[ ] Cleanup returned iptables to a clean state
[ ] Any adjustments needed: ____________
```

---

## Fallback (if RCF anomaly is not triggering during the demo)

If the OpenSearch detector is still in `INIT` state and not producing
anomalies, use the Phase 4 dry-run test to demonstrate the agent and
Cedar sandbox layers independently — it does not require a live detector:

```bash
python tests/test_phase4_dry_run.py
```

This validates the hybrid reasoning agent, Cedar syntax + semantic sandbox,
and the audit log in a self-contained offline mode. Describe this to the
audience as "the unit-tested half of the pipeline" and explain that the
sniffer-to-daemon chain requires a pre-warmed RCF detector.
