#!/usr/bin/env python3
"""Recalibrate the Zisk per-proof floor and marginal throughput from measurement.

`BASE_COST` in zisk's `emulator/src/emu_costs.rs` is
`ROM_COST + TABLES_COST = (21 << 21) + ((55 + 35 + 29) << 21) = 293,601,280`.
It is a *model* of the trace area every proof pays regardless of its workload,
and `ziskemu -X` prints it as `BASE`. Nothing in the prover reads it.

This script fits it from the other end: sweep one guest across many workload
sizes, regress time on the *variable* cost only, and read the floor off the
intercept. Fitting against `TOTAL` instead would be circular, because `TOTAL`
already contains the constant under test.

Two regressions are run, because they answer different questions:

  wall clock       what an implementation that shells out per proof pays. Its
                   intercept is process start + GPU allocation + the floor.
  `Proof generated` the prover's own figure for the proof, after
                   `INITIALIZING_PROOFMAN` has allocated the GPU. Its intercept
                   is the floor alone, and multiplying it by the fitted rate is
                   the measured equivalent of `BASE_COST`.

Usage:
    python3 scripts/fit_gpu_bench.py [--dir data/gpu_bench]
"""
import argparse
import csv
import math
import os
import statistics as st

CLAIMED_BASE_COST = 293_601_280   # zisk emulator/src/emu_costs.rs
CLAIMED_RATE = 67_452_592         # units/s, BENCHMARKS.md
CLAIMED_COLD_FIXED_S = 19.52      # scripts/streaming_cost.py


def read_costs(path):
    out = {}
    with open(path) as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) >= 5:
                out[int(row[0])] = tuple(int(x) for x in row[1:5])
    return out


def read_times(path):
    out = {}
    with open(path) as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) >= 5 and row[4] == "0":
                out.setdefault(int(row[0]), []).append(float(row[3]))
    return out


def read_phases(path):
    """prove_bench_<n>_<rep>.log -> {phase: seconds}"""
    if not path or not os.path.exists(path):
        return {}
    out = {}
    with open(path) as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    for r in rows:
        name = r["log"]
        if not name.startswith("prove_bench_"):
            continue
        try:
            n = int(name[len("prove_bench_"):].rsplit("_", 1)[0])
        except ValueError:
            continue
        vals = {k: float(v) for k, v in r.items() if k != "log" and v not in ("", None)}
        out.setdefault(n, []).append(vals)
    return out


def ols(xs, ys):
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    b = sxy / sxx
    a = my - b * mx
    resid = [y - (a + b * x) for x, y in zip(xs, ys)]
    if n > 2:
        s2 = sum(r * r for r in resid) / (n - 2)
        return a, b, math.sqrt(s2 * (1.0 / n + mx * mx / sxx)), math.sqrt(s2 / sxx), resid
    return a, b, float("nan"), float("nan"), resid


def report(label, xs, ys, note):
    a, b, se_a, se_b, resid = ols(xs, ys)
    rate, se_rate = 1.0 / b, se_b / (b * b)
    rms = math.sqrt(sum(r * r for r in resid) / len(resid))
    print(f"\n=== fit: {label} = floor + VARIABLE / rate ===")
    print(f"  {note}")
    print(f"  points           {len(xs)} sizes, {min(xs):,} .. {max(xs):,} variable units")
    print(f"  floor            {a:9.3f} s  +/- {se_a:.3f} (1 s.e.)")
    print(f"  rate           {rate:13,.0f} units/s  +/- {se_rate:,.0f}")
    print(f"  residual rms     {rms:9.3f} s   range {min(resid):+.3f} .. {max(resid):+.3f}")
    return a, rate, se_a, se_rate, resid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="data/gpu_bench")
    ap.add_argument("--phases", default=None,
                    help="TSV from scripts/parse_prove_logs.py (default: <dir>/bench_phases.tsv)")
    args = ap.parse_args()

    costs = read_costs(os.path.join(args.dir, "bench_costs.tsv"))
    walls = read_times(os.path.join(args.dir, "bench_times.tsv"))
    phases = read_phases(args.phases or os.path.join(args.dir, "bench_phases.tsv"))

    rows = []
    for n in sorted(walls):
        if n not in costs:
            continue
        steps, variable, base, total = costs[n]
        w = walls[n]
        ph = phases.get(n, [])
        gen = [p["PROOF_GENERATED"] for p in ph if "PROOF_GENERATED" in p]
        init = [p["INITIALIZING_PROOFMAN"] for p in ph if "INITIALIZING_PROOFMAN" in p]
        rows.append({
            "n": n, "variable": variable, "total": total, "steps": steps,
            "wall": w, "gen": gen, "init": init,
        })

    print(f"{'n':>9} {'VARIABLE':>14} {'TOTAL':>14} {'wall_s':>7} {'sd':>5} "
          f"{'prove_s':>8} {'sd':>5} {'init_s':>7}")
    for r in rows:
        wm, wsd = st.mean(r["wall"]), (st.stdev(r["wall"]) if len(r["wall"]) > 1 else 0)
        gm = st.mean(r["gen"]) if r["gen"] else float("nan")
        gsd = st.stdev(r["gen"]) if len(r["gen"]) > 1 else 0
        im = st.mean(r["init"]) if r["init"] else float("nan")
        print(f"{r['n']:>9} {r['variable']:>14,} {r['total']:>14,} {wm:>7.2f} {wsd:>5.2f} "
              f"{gm:>8.2f} {gsd:>5.2f} {im:>7.2f}")

    xs = [r["variable"] for r in rows]
    a_w, rate_w, se_aw, se_rw, resid_w = report(
        "wall clock", xs, [st.mean(r["wall"]) for r in rows],
        "what a shell-out-per-proof implementation pays")

    have_gen = all(r["gen"] for r in rows)
    if have_gen:
        a_g, rate_g, se_ag, se_rg, resid_g = report(
            "prover 'Proof generated'", xs, [st.mean(r["gen"]) for r in rows],
            "GPU already allocated; intercept is the AIR floor alone")
    else:
        print("\n(no PROOF_GENERATED data; run scripts/parse_prove_logs.py first)")
        a_g = rate_g = se_ag = None

    # Quantisation makes one global line slightly wrong: each extra Main
    # instance is a step, so the honest slope is measured inside one regime.
    MAIN_ROWS_ = 1 << 22
    regime = [r for r in rows if -(-r["steps"] // MAIN_ROWS_) == 1 and r["gen"]]
    if len(regime) >= 3:
        a_r, rate_r, se_ar, se_rr, _ = report(
            "prover 'Proof generated', single-Main-instance sizes only",
            [r["variable"] for r in regime], [st.mean(r["gen"]) for r in regime],
            f"{len(regime)} sizes below the first AIR-instance step")
        print(f"  floor in cost units          {a_r*rate_r:>14,.0f}")

    print("\n=== the per-proof floor, in cost units ===")
    print(f"  claimed BASE_COST                 {CLAIMED_BASE_COST:>14,}")
    if a_g is not None:
        measured = a_g * rate_g
        lo = (a_g - se_ag) * rate_g
        hi = (a_g + se_ag) * rate_g
        print(f"  measured floor {a_g:.3f}s x {rate_g:,.0f}/s  {measured:>14,.0f}"
              f"   [{lo:,.0f} .. {hi:,.0f}]")
        print(f"  error in BASE_COST                {100*(CLAIMED_BASE_COST-measured)/measured:>+13.1f}%")
    init_all = [v for r in rows for v in r["init"]]
    if init_all:
        print(f"\n=== cold/warm gap (measured) ===")
        print(f"  INITIALIZING_PROOFMAN mean        {st.mean(init_all):>8.2f} s "
              f"(n={len(init_all)}, sd {st.stdev(init_all):.2f})")
        gen_all = [v for r in rows for v in r["gen"]]
        wall_all = [v for r in rows for v in r["wall"]]
        if gen_all:
            print(f"  mean wall                         {st.mean(wall_all):>8.2f} s")
            print(f"  mean 'Proof generated'            {st.mean(gen_all):>8.2f} s")
            print(f"  per-invocation overhead           "
                  f"{st.mean(wall_all)-st.mean(gen_all):>8.2f} s  <- what a warm prover saves")
        print(f"  published GPU_COLD_FIXED_S        {CLAIMED_COLD_FIXED_S:>8.2f} s")

    print("\n=== residual scan for AIR-instance quantisation ===")
    print(f"{'n':>9} {'VARIABLE':>14} {'wall_s':>8} {'resid':>8} {'prove_s':>8} {'resid':>8}")
    for i, r in enumerate(rows):
        rg = f"{resid_g[i]:+8.3f}" if a_g is not None else "       -"
        print(f"{r['n']:>9} {r['variable']:>14,} {st.mean(r['wall']):>8.2f} "
              f"{resid_w[i]:>+8.3f} "
              f"{st.mean(r['gen']) if r['gen'] else float('nan'):>8.2f} {rg}")

    # The prover instantiates whole AIRs. Main is the AIR that tracks executed
    # steps, and the shipped v1.0.0-alpha key sizes it at 2^22 rows, so a proof
    # needs ceil(STEPS / 2^22) Main instances and time should step there rather
    # than scale smoothly across the boundary.
    MAIN_ROWS = 1 << 22
    print("\n=== predicted AIR-instance boundaries (Main at 2^22 rows) ===")
    crossed = False
    for lo, hi in zip(rows, rows[1:]):
        i_lo = -(-lo["steps"] // MAIN_ROWS)
        i_hi = -(-hi["steps"] // MAIN_ROWS)
        if i_lo != i_hi:
            crossed = True
            dt = (st.mean(hi["gen"]) - st.mean(lo["gen"])) if (lo["gen"] and hi["gen"]) else float("nan")
            dv = hi["variable"] - lo["variable"]
            print(f"  n {lo['n']:,} -> {hi['n']:,}: Main instances {i_lo} -> {i_hi}, "
                  f"d_prove {dt:+.3f}s for {dv:,} variable units")
    if not crossed:
        print("  (the sweep does not cross one)")

    print("\n=== consecutive deltas (a flat run then a jump means quantisation) ===")
    print(f"{'n_lo':>9} {'n_hi':>9} {'d_VARIABLE':>14} {'d_prove_s':>10} {'implied_rate':>14}")
    for lo, hi in zip(rows, rows[1:]):
        if not (lo["gen"] and hi["gen"]):
            continue
        dv = hi["variable"] - lo["variable"]
        dt = st.mean(hi["gen"]) - st.mean(lo["gen"])
        impl = dv / dt if abs(dt) > 1e-9 else float("inf")
        print(f"{lo['n']:>9} {hi['n']:>9} {dv:>14,} {dt:>+10.3f} {impl:>14,.0f}")

    published_vs_measured(rows)


def published_vs_measured(rows):
    """How the shipped model does against the measurements it is supposed to predict.

    The published model is `time = TOTAL / 67,452,592` for the proving itself,
    with `TOTAL = VARIABLE + 293,601,280`. If BASE_COST understates the floor,
    the error should be worst on the smallest proofs, where the floor is most of
    the work.
    """
    print("\n=== published model vs measurement (prove time only) ===")
    print(f"{'n':>9} {'TOTAL':>14} {'predicted_s':>12} {'measured_s':>11} {'error':>9}")
    worst = 0.0
    for r in rows:
        if not r["gen"]:
            continue
        pred = r["total"] / CLAIMED_RATE
        meas = st.mean(r["gen"])
        err = 100 * (pred - meas) / meas
        worst = max(worst, abs(err))
        print(f"{r['n']:>9} {r['total']:>14,} {pred:>12.2f} {meas:>11.2f} {err:>+8.1f}%")
    print(f"  worst absolute error {worst:.1f}%")


if __name__ == "__main__":
    main()
