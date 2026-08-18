#!/usr/bin/env python3
"""Whole-system health for zkasper, in one line per component.

health.py answers "is the daemon working" from its manifest. This answers "is
the service working", which is a larger question: the daemon, the rented GPU and
what it is costing, the API, and the public site. It is what a cron job runs.

    ./scripts/monitor.py                      # human output
    ./scripts/monitor.py --json               # for a cron to diff against
    ./scripts/monitor.py --quiet              # print only what is wrong

Exit code is 0 when everything is clear and 1 when anything is not, so cron can
notify on the exit code alone.

Nothing here writes anything or spends anything. Read-only by construction.
"""
import argparse, json, os, re, subprocess, sys, time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

STATUS = "/mnt/ssd/zkasper-run/out/status.json"
VAST_KEY_FILE = "/root/.openclaw/workspace/.vast-api"
API = "https://api.zkasper.com/v1/status"
SITE = "https://zkasper.com"
STALE_S = 120


def check(name, ok, detail):
    return {"name": name, "ok": bool(ok), "detail": detail}


def daemon():
    """The daemon, from the manifest it rewrites after every stage."""
    try:
        s = json.loads(Path(STATUS).read_text())
    except Exception as e:
        return [check("daemon", False, f"no manifest: {e}")]

    out, age = [], time.time() - s.get("updated_unix", 0)
    out.append(check("daemon", age <= STALE_S,
                     f"epoch {(s.get('accumulator') or {}).get('epoch')}, "
                     f"head {s.get('head_slot')}, manifest {age:.0f}s old"))

    g = s.get("gossip") or {}
    if g:
        dropped = g.get("dropped", 0)
        out.append(check("gossip", dropped == 0,
                         f"dropped {dropped}, reconnects {g.get('reconnects', 0)}"))

    lat = s.get("recent_latencies") or []
    if lat:
        last = lat[-1]
        # late_groups marks a catch-up epoch, not a steady-state one, so it is
        # reported rather than paged on. Sustained non-zero means the daemon is
        # not keeping up with the chain.
        recent_late = sum(1 for l in lat[-5:] if l.get("late_groups"))
        out.append(check("latency", recent_late < 5,
                         f"T2-T {last.get('t2_minus_t_millis')}ms, "
                         f"tail {last.get('tail_named')}, "
                         f"late in last {min(len(lat),5)}: {recent_late}"))

    pub = s.get("publish") or {}
    if pub:
        out.append(check("publish", pub.get("dropped", 0) == 0,
                         f"posted {pub.get('posted',0)}, spooled {pub.get('spooled',0)}, "
                         f"dropped {pub.get('dropped',0)}, pending {pub.get('pending',0)}"))
    return out


def gpus():
    """Rented instances and what they are burning. Silence here costs money."""
    try:
        key = re.search(r"[a-f0-9]{64}", Path(VAST_KEY_FILE).read_text()).group(0)
    except Exception:
        return [check("gpu", True, "no vast key, not checked")]
    env = {**os.environ, "VAST_API_KEY": key}
    try:
        raw = subprocess.run(["vastai", "show", "instances", "--raw"],
                             capture_output=True, text=True, timeout=45, env=env).stdout
        inst = json.loads(raw) if raw.strip() else []
        credit = json.loads(subprocess.run(["vastai", "show", "user", "--raw"],
                                           capture_output=True, text=True,
                                           timeout=45, env=env).stdout).get("credit", 0)
    except Exception as e:
        return [check("gpu", False, f"vast query failed: {e}")]

    burn = sum(i.get("dph_total") or 0 for i in inst)
    what = ", ".join(f"{i['id']} {i.get('actual_status')}" for i in inst) or "none"
    out = [check("gpu", True, f"{len(inst)} instance(s): {what} | ${burn:.2f}/hr")]
    # A card left running overnight is the expensive failure, so credit that
    # cannot cover another day is worth surfacing before it runs out.
    out.append(check("credit", credit > burn * 24 if burn else credit > 0,
                     f"${credit:.2f}" + (f", {credit/burn:.0f}h left at this burn" if burn else "")))
    return out


def url(name, u, want):
    # Cloudflare rejects urllib's default agent, so the check would fail on
    # a healthy site. Identify honestly rather than impersonating a browser.
    req = Request(u, headers={"User-Agent": "zkasper-monitor"})
    try:
        with urlopen(req, timeout=20) as r:
            body = r.read(200_000)
            return check(name, r.status == 200, f"HTTP {r.status}, {len(body)} bytes"
                         + (f", {want(body)}" if want else ""))
    except (URLError, HTTPError, TimeoutError) as e:
        return check(name, False, f"unreachable: {e}")


def api_detail(body):
    d = json.loads(body)
    if not d.get("chain"):
        return "empty, no daemon has published"
    return f"chain {d.get('chain')}, epoch {(d.get('accumulator') or {}).get('epoch')}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="print only failures")
    a = ap.parse_args()

    checks = daemon() + gpus() + [url("api", API, api_detail), url("site", SITE, None)]
    healthy = all(c["ok"] for c in checks)

    if a.json:
        print(json.dumps({"ok": healthy, "checks": checks}, indent=2))
    else:
        for c in checks:
            if a.quiet and c["ok"]:
                continue
            print(f"{'ok  ' if c['ok'] else 'FAIL'}  {c['name']:<9} {c['detail']}")
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
