"""
autoresearch verify: check tlog last 5min for risk/crash events
Output: 1 = pass (no risk, app running)  0 = fail
"""
import urllib.request, time, re, sys, datetime

TLOG_URL = "http://49.234.20.227:8888/logs"
WINDOW_SECS = 300

RISK_EVENTS    = ["ssl_resp", "exit_block", "abort_block", "kill_block"]
CRASH_SIGNALS  = ["exit_blocked", "abort_blocked", "kill_blocked"]
HEALTHY_EVENTS = ["resp_done", "resp_data"]

def fetch_logs():
    try:
        with urllib.request.urlopen(TLOG_URL, timeout=8) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[verify] fetch failed: {e}", file=sys.stderr)
        return ""

def parse_recent(html, window=WINDOW_SECS):
    now = time.time()
    lines = re.findall(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(\w+)\] (\w+)', html)
    recent = []
    for ts_str, device, event in lines:
        try:
            ts = datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
        except:
            continue
        if now - ts <= window:
            recent.append((ts, device, event))
    return recent

def score(recent):
    if not recent:
        print("[verify] no recent events - user needs to run the app first")
        return 0

    risk   = [e for e in recent if e[2] in RISK_EVENTS]
    crash  = [e for e in recent if e[2] in CRASH_SIGNALS]
    health = [e for e in recent if e[2] in HEALTHY_EVENTS]
    profile_ok = [e for e in recent if e[2] == "profile_ok"]
    kc_blocked = [e for e in recent if e[2] == "kc_blocked"]

    print(f"[verify] events: healthy={len(health)}, risk={len(risk)}, crash={len(crash)}, profile_ok={len(profile_ok)}, kc_blocked={len(kc_blocked)}")

    if crash:
        print(f"[verify] FAIL crash signal: {[e[2] for e in crash[:3]]}")
        return 0
    if risk:
        print(f"[verify] FAIL risk event: {[e[2] for e in risk[:3]]}")
        return 0
    if len(health) < 3:
        print("[verify] WARN too few health events")
        return 0

    print("[verify] PASS no risk, app running normally")
    return 1

if __name__ == "__main__":
    html = fetch_logs()
    recent = parse_recent(html)
    result = score(recent)
    print(result)
    sys.exit(0 if result == 1 else 1)
