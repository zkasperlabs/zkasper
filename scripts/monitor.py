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

DEFAULT_STATUS = "/mnt/ssd/zkasper-run/out/status.json"


def status_path():
    """Where the *running* daemon writes, not where one used to.

    A hardcoded path made this check fail loudly the moment the daemon was
    restarted with a different --output-dir, which is the fastest way to teach
    an operator to ignore an alert. Ask the process instead, and return None
    when nothing is running.

    Matching on the command line is not enough: the supervisor is a shell whose
    own argv contains the daemon's path, so a substring match finds it, fails to
    see --output-dir in a shell's arguments, and silently falls back. That is
    how this check read an 84-minute-old manifest as current while the daemon
    was crashlooping. Resolve /proc/PID/exe instead, which only the real binary
    satisfies.
    """
    try:
        # Not a path fragment: "release/zkasperd" went blind the moment
        # production moved to a pinned binary at bin/zkasperd, reporting a
        # healthy daemon as dead. Match the name, let /proc/PID/exe judge.
        pids = subprocess.run(["pgrep", "-x", "zkasperd"],
                              capture_output=True, text=True, timeout=15).stdout.split()
        for pid in pids:
            try:
                if not Path(f"/proc/{pid}/exe").resolve().name.startswith("zkasperd"):
                    continue
            except OSError:
                continue
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            for i, a in enumerate(argv):
                if a == b"--output-dir" and i + 1 < len(argv):
                    out = Path(argv[i + 1].decode())
                    # Only the production daemon counts. A test or dry-run
                    # zkasperd matches `pgrep -x` just as well, and on
                    # 2026-08-19 one was reporting `epoch 10, head 426` --
                    # fixture values -- as production health while production
                    # was down for a deploy. Anchor on where it writes.
                    if PRODUCTION_OUT not in (str(out), str(out.resolve())):
                        continue
                    return str(out / "status.json")
    except Exception:
        pass
    return None


def daemon_running():
    return status_path() is not None
PRODUCTION_OUT = "/mnt/ssd/zkasper-run/out-remote"
VAST_KEY_FILE = "/root/.openclaw/workspace/.vast-api"
API = "https://api.zkasper.com/v1/status"
METRICS = "http://127.0.0.1:9464/metrics"
SITE = "https://zkasper.com"
# Liveness comes from the daemon's heartbeat, not from its manifest. The
# manifest is only rewritten when a stage *finishes*, and stages legitimately
# run for minutes — a committee proof is ~127 s and a batch justification 1,224 s
# — so every manifest-based threshold has fired on a healthy daemon. The
# heartbeat is written once a second by its own task and means only "the process
# is alive", which is the question being asked.
HEARTBEAT_STALE_S = 90
# The manifest is still worth a much looser bound: no stage finishing for half an
# hour means the pipeline is stuck even if the process breathes.
STALE_S = 1800


def check(name, ok, detail):
    return {"name": name, "ok": bool(ok), "detail": detail}


def heartbeat_age():
    """Seconds since the daemon last breathed, or None if it serves no metrics."""
    try:
        req = Request(METRICS, headers={"User-Agent": "zkasper-monitor"})
        with urlopen(req, timeout=10) as r:
            for line in r.read().decode().splitlines():
                if line.startswith("zkasper_heartbeat_timestamp_seconds "):
                    return time.time() - float(line.split()[1])
    except Exception:
        pass
    return None


def daemon():
    """The daemon, from the manifest it rewrites after every stage."""
    path = status_path()
    # A stale manifest read as if it were current is worse than no reading at
    # all: on 2026-08-18 this reported a healthy-looking epoch for 84 minutes
    # while the daemon was crashlooping and four rented GPUs sat idle.
    if path is None:
        return [check("daemon", False, "no zkasperd process running")]
    try:
        s = json.loads(Path(path).read_text())
    except Exception as e:
        return [check("daemon", False, f"no manifest at {path}: {e}")]

    out, age = [], time.time() - s.get("updated_unix", 0)
    beat = heartbeat_age()
    # No endpoint is a failure, not a reading to be taken another way. A process
    # in /proc is not liveness: a run that has already ended stays there, threads
    # and all, until the runtime finishes waiting on the blocking work it
    # started, and for the whole of that it serves no metrics. Falling back to
    # the manifest here is what reported a dead run as
    # "ok daemon ... no heartbeat endpoint" on 2026-08-19, three crashes in a
    # row. If the daemon is not answering, that is the finding.
    out.append(check("daemon", beat is not None and beat <= HEARTBEAT_STALE_S,
                     f"epoch {(s.get('accumulator') or {}).get('epoch')}, "
                     f"head {s.get('head_slot')}, "
                     + (f"heartbeat {beat:.0f}s ago" if beat is not None
                        else "no heartbeat endpoint: the process is not serving metrics, "
                             "which is what a shutting-down or wedged daemon looks like")))
    out.append(check("pipeline", age <= STALE_S,
                     f"last stage finished {age:.0f}s ago"))

    g = s.get("gossip") or {}
    if g:
        # `dropped` is not reported. It has been 0 on every check ever taken,
        # --http-sse-capacity-multiplier 2000 makes it structurally unable to
        # fire, and it stayed 0 through the worst data loss this project has had
        # -- the collector discarding every network aggregate, ~35 points of
        # stake missing and four justified epochs skipped. It measures the SSE
        # ring, not whether attestations are used, so a green reading here is
        # evidence of nothing. `reconnects` still tells you the node bounced.
        out.append(check("gossip", True,
                         f"reconnects {g.get('reconnects', 0)}"))

    s_manifest = s
    lat = s.get("recent_latencies") or []
    if lat:
        last = lat[-1]
        # late_groups == 1 is the schedule's own optimum, not a shortfall: the
        # planner prints "Final absorbs [1]" on mainnet, and folding that last
        # group would cost a stage floor plus a recursion (56.7 s) more. This
        # check paged on every healthy epoch until 2026-08-19. Only 2 or more is
        # a real signal, since the fire path holds at most one group and a
        # second means the pipeline is behind.
        # folded_groups is a readout of prover latency, not of attestation volume:
        # a group is however many slots piled up while the previous proof ran, so
        # 1 is the healthy shape and a large number means the cycle time collapsed.
        # Epoch 469539 folded 19 against dead provers and still published as
        # "proven" -- the fold count said so before anything else did.
        worst_folded = max((l.get("folded_groups") or 0) for l in lat[-5:])
        out.append(check("cycle", worst_folded <= 5,
                         f"worst folded_groups in last {min(len(lat),5)}: {worst_folded}"
                         + ("" if worst_folded <= 5 else " -- the prover is answering too fast to be proving")))
        worst_late = max((l.get("late_groups") or 0) for l in lat[-5:])
        # The three that matter: every epoch proven, and the cost and time of
        # proving them. Everything else here is plumbing.
        out.append(check("folds", worst_late < 2,
                         f"worst late_groups in last {min(len(lat),5)}: {worst_late}"))

    # How far behind the chain the daemon closes an epoch, and which way it is
    # moving. This is the signal `T2 - T` mostly measures and the one an operator
    # can act on: an epoch closed 3.5 epochs late is a backlog, not a slow proof,
    # and the only question that matters is whether the backlog is shrinking.
    # Measured 2026-08-19: 3.89 epochs late, then 3.55, gaining 0.34 an epoch on
    # one card at an 87% duty cycle -- an hour to catch up, and hours behind
    # after any hiccup.
    #
    # `slot_seconds` and genesis come out of the data rather than a constant:
    # `threshold_unix_millis` is by construction `genesis + slot * slot_seconds`,
    # so two epochs of latency determine both, and the check cannot drift from
    # the chain the daemon is actually following.
    done = [l for l in lat if l.get("t2_minus_t_millis")]
    if len(done) >= 2:
        a, b = done[-2], done[-1]
        span_slots = b["threshold_slot"] - a["threshold_slot"]
        slot_s = ((b["threshold_unix_millis"] - a["threshold_unix_millis"]) / 1000
                  / span_slots) if span_slots else 0
        if slot_s > 0:
            spe = 32
            genesis = b["threshold_unix_millis"] / 1000 - b["threshold_slot"] * slot_s
            lag = [(l["proof_unix_millis"] / 1000
                    - (genesis + l["epoch"] * spe * slot_s)) / (spe * slot_s)
                   for l in done[-4:]]
            trend = lag[-1] - lag[0]
            out.append(check("lag", trend <= 0 or lag[-1] < 1.0,
                             f"closes {lag[-1]:.2f} epochs behind the chain, "
                             + (f"gaining {-trend / max(len(lag) - 1, 1):.2f} an epoch"
                                if trend < 0 else
                                f"LOSING {trend / max(len(lag) - 1, 1):.2f} an epoch")))

    # Cost per epoch: sum the prover time of a whole epoch's stages and price it.
    stages = s.get("recent_stages") or []
    rate = s.get("prover_usd_per_hour")
    if not stages:
        out.append(check("cost", True, "no stage priced yet"))
    if stages and rate:
        by_epoch = {}
        for st in stages:
            by_epoch.setdefault(st.get("epoch"), 0)
            by_epoch[st["epoch"]] += st.get("prove_millis") or 0
        full = [v for v in by_epoch.values() if v]
        if full:
            avg = sum(full) / len(full)
            out.append(check("cost", True,
                             f"${avg / 3_600_000 * rate:.4f}/epoch, "
                             f"{avg / 1000:.0f}s prover over {len(full)}"))

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


def published_latency():
    """The `T2 - T` distribution, from the API rather than the manifest.

    The criterion asks for median and p90 over **at least 100 epochs**, and the
    daemon's manifest keeps the last **ten** — so nothing could measure it until
    this read the published feed instead. The API holds every epoch of the run
    and is what a consumer sees, which makes it the right source anyway.

    Two windows, because they answer different questions. A run starts behind
    the chain and spends ~7 epochs closing the backlog, during which `T2 - T` is
    the backlog and not the pipeline: 892 s falling to 60 s on 2026-08-19. The
    all-time figure is what the criterion wants and stays dragged by that tail
    for hours. The trailing figure is what tells an operator whether steady state
    has degraded, and it is the one that moves first when something breaks.
    """
    try:
        epochs, before = [], None
        while len(epochs) < 400:
            url = "https://api.zkasper.com/v1/epochs?limit=200"
            if before is not None:
                url += f"&before={before}"
            req = Request(url, headers={"User-Agent": "zkasper-monitor"})
            with urlopen(req, timeout=30) as r:
                page = json.loads(r.read())
            epochs.extend(page.get("epochs", []))
            before = page.get("next_before")
            if before is None:
                break
        req = Request("https://api.zkasper.com/v1/status",
                      headers={"User-Agent": "zkasper-monitor"})
        with urlopen(req, timeout=25) as r:
            init = json.loads(r.read()).get("init_epoch")
    except Exception as e:
        return check("time", True, f"not checked: {e}")

    # Since the current init point only: epochs below it belong to a chain that
    # was abandoned, and their latency describes a run that no longer exists.
    # Chronological first, then sorted for the percentiles. Slicing a sorted
    # list for "the last ten" takes the ten slowest, which is exactly backwards
    # for a check meant to notice steady state degrading.
    live = [e["latency"] for e in epochs
            if (e.get("latency") or {}).get("t2_minus_t_millis")
            and (init is None or e.get("epoch", 0) >= init)]
    series = sorted(((l["epoch"], l["t2_minus_t_millis"] / 1000) for l in live),
                    key=lambda row: row[0])
    v = sorted(t for _, t in series)
    if len(v) < 3:
        return check("time", True, f"{len(v)} epochs measured since init, too few")
    recent = sorted(t for _, t in series[-10:])
    return check("time", True,
                 f"T2-T median {v[len(v) // 2]:.0f}s "
                 f"p90 {v[int(0.9 * (len(v) - 1))]:.0f}s over {len(v)}"
                 f" ({len(v)}/100 for the criterion)"
                 + (f", last {len(recent)} median {recent[len(recent) // 2]:.0f}s"
                    if len(v) > 10 else "")
                 + latency_split(live))


def latency_split(latencies):
    """Where the median epoch's `T2 - T` went, term by term.

    The distribution alone says the number is large and nothing about which of
    the five things it is made of, and they have different owners: observation
    and blocked are the daemon's schedule, wait is the trigger rule, and the
    final proof is the prover. Reported as the median of each term rather than
    the terms of the median epoch -- they will not sum to the median `T2 - T`,
    and each one is still the right summary of its own column.

    Rows from a daemon before 2026-08-19 have no `blocked_millis` and carry it
    inside `wait_millis`; they are skipped rather than mixed in, since a wait of
    30 s and a wait of 79 ms are not samples of the same quantity.
    """
    terms = ("observation_millis", "blocked_millis", "wait_millis",
             "late_group_millis", "final_proof_millis")
    split = [l for l in latencies if all(l.get(t) is not None for t in terms)]
    if not split:
        return ""
    med = {t: sorted(l[t] for l in split)[len(split) // 2] / 1000 for t in terms}
    return (f"; median split over {len(split)}: "
            + " ".join(f"{name} {med[t]:.1f}s" for name, t in
                       zip(("observing", "blocked", "waiting", "late group", "final proof"),
                           terms)))


def published_gaps():
    """Epochs the chain justified but no proof exists for.

    Nothing watched this until 2026-08-19, which is how a collector bug that
    discarded every network aggregate ran for a whole night: it abandoned four
    epochs at 62-76% support while `gossip.dropped` stayed 0 and every other
    check stayed green. A consumer cannot detect a missing epoch for themselves,
    so the hole has to be found here.
    """
    # Page the whole run, not a window. This read the last 40 epochs, and on
    # 2026-08-19 the run passed 40 and the window slid off the init point -- so
    # from then on a hole would have scrolled out of view unnoticed, on the one
    # check whose entire job is to notice holes. The criterion is over 100+
    # epochs; the check has to be too.
    try:
        d = {"epochs": []}
        before = None
        while len(d["epochs"]) < 400:
            url = "https://api.zkasper.com/v1/epochs?limit=200"
            if before is not None:
                url += f"&before={before}"
            req = Request(url, headers={"User-Agent": "zkasper-monitor"})
            with urlopen(req, timeout=30) as r:
                page = json.loads(r.read())
            d["epochs"].extend(page.get("epochs", []))
            before = page.get("next_before")
            if before is None:
                break
        req = Request("https://api.zkasper.com/v1/status",
                      headers={"User-Agent": "zkasper-monitor"})
        with urlopen(req, timeout=25) as r:
            init = json.loads(r.read()).get("init_epoch")
    except Exception as e:
        return check("chain", True, f"not checked: {e}")
    # Judge the current run, not everything the API ever indexed. A fresh init
    # point starts a new accumulator chain, and every epoch below it belongs to
    # a chain that was deliberately abandoned -- reporting those as holes makes
    # this check fail for ever after a legitimate cold start, which is how an
    # operator learns to ignore it. The restart itself is named in the detail so
    # a broken chain is still visible rather than filtered away.
    epochs = [e for e in d.get("epochs", [])
              if init is None or e.get("epoch", 0) >= init]
    if not epochs:
        return check("chain", True, f"no epoch published since the init at {init}")
    nums = sorted(e["epoch"] for e in epochs if e.get("status") == "proven")
    # An epoch that closed without a proof is the same hole, published rather
    # than absent. It is named apart because the two are fixed differently: a
    # gap is an epoch the daemon never finished, and `unproven` is one it
    # finished with no prover behind it.
    unproven = sorted(e["epoch"] for e in epochs if e.get("status") == "unproven")
    if len(nums) < 2:
        return check("chain", not unproven,
                     f"{len(nums)} proven since init {init}, too few to judge"
                     + (f", UNPROVEN {unproven}" if unproven else ""))
    # `stranded` is an epoch a dead daemon left open and the API has since closed
    # out on its behalf. It is still a hole in the proof chain -- no proof exists
    # for it -- so it still fails, but it is named apart from `HOLES`, because
    # the two say different things about the index: a hole is an epoch nobody
    # ever published, and a stranded one was published and then correctly
    # disowned. `abandoned` is deliberately *not* counted as known: an epoch the
    # chain never justified is the fault this check was written to find.
    stranded = sorted(e["epoch"] for e in epochs if e.get("status") == "stranded")
    known = set(nums) | set(unproven) | set(stranded)
    missing = [n for n in range(nums[0], nums[-1]) if n not in known]
    # An epoch left in `proving` below the proven high-water mark is one the
    # daemon has moved past and nothing will ever finish. To a consumer it reads
    # exactly like one still in flight, so they poll for ever. 469570 got there by
    # being proved while the daemon ran with a truncated argv and no --api-url, so
    # it was neither published nor spooled; twelve more had accumulated by
    # 2026-08-19 before the API had a word for them.
    #
    # The API now marks these `stranded` on the first batch that moves its own
    # high-water mark, so this list is empty in the steady state. It is non-empty
    # for exactly two reasons, and both are worth waking up for: a daemon that is
    # down right now and has not yet been outlived by a successor, or a reaper
    # that has stopped working and is lying to consumers again.
    stuck = sorted(e["epoch"] for e in epochs
                   if e.get("status") == "proving" and e["epoch"] < nums[-1])
    bits = [f"proven {nums[0]}-{nums[-1]} since init {init}"]
    if missing:
        bits.append(f"HOLES at {missing}")
    if unproven:
        bits.append(f"UNPROVEN {unproven}")
    if stranded:
        bits.append(f"STRANDED {stranded}")
    if stuck:
        bits.append(f"STUCK proving, unreaped {stuck}")
    if not (missing or unproven or stranded or stuck):
        bits.append("contiguous")
    return check("chain", not (missing or unproven or stranded or stuck), ", ".join(bits))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="print only failures")
    a = ap.parse_args()

    checks = (daemon() + gpus()
              + [url("api", API, api_detail), published_latency(), published_gaps(),
                 url("site", SITE, None)])
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
