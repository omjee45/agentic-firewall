
LOGS_FILE="logs/applied_rules.json"
HARD=false

for arg in "$@"; do
    if [ "$arg" == "--hard" ]; then
        HARD=true
    fi
done

echo "=== iptables INPUT (before cleanup) ==="
iptables -L INPUT -n -v 2>/dev/null || echo "[WARN] iptables not available or no permission (try sudo)"
echo ""

if [ -f "$LOGS_FILE" ]; then
    echo "Reading $LOGS_FILE for ACTIVE rules..."

    python3 - <<'EOF'
import json, sys, subprocess, os

log_file = "logs/applied_rules.json"
try:
    with open(log_file) as f:
        records = json.load(f)
except Exception as e:
    print(f"[WARN] Could not read {log_file}: {e}")
    sys.exit(0)

reverted = 0
for r in records:
    if r.get("status") == "ACTIVE":
        ip = r.get("target_ip")
        if not ip:
            continue
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        print(f"Reverting: {' '.join(cmd)}")
        result = subprocess.run(cmd, stderr=subprocess.PIPE)
        if result.returncode == 0:
            print(f"  OK: removed ban for {ip}")
            reverted += 1
        else:
            err = result.stderr.decode().strip()
            print(f"  SKIPPED (rule may not exist): {err}")

print(f"\n{reverted} rule(s) reverted.")
EOF
else
    echo "[INFO] No log file found at $LOGS_FILE — nothing to revert."
fi

echo ""
echo "=== iptables INPUT (after cleanup) ==="
iptables -L INPUT -n -v 2>/dev/null || echo "[WARN] iptables not available"
echo ""

# --hard: also wipe the JSON log
if [ "$HARD" = true ]; then
    echo "[--hard] Resetting $LOGS_FILE to empty list..."
    mkdir -p logs
    echo "[]" > "$LOGS_FILE"
    echo "Done. Audit log cleared."
fi

echo "Cleanup complete."
