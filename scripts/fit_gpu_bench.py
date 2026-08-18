#!/usr/bin/env python3
"""Fit `time = floor + variable_cost / rate` from a GPU bench sweep.

Consumes the TSVs written by `scripts/gpu_bench.sh`'s sweep (see
`data/gpu_bench/`) and reports the fitted floor and marginal throughput with
standard errors, plus a residual scan for AIR-instance quantisation steps.

Usage:
    python3 scripts/fit_gpu_bench.py [--dir data/gpu_bench]
"""
import argparse
import csv
import math
import os
import statistics as st

CLAIMED_BASE_COST = 293_601_280      # zisk emulator/src/emu_costs.rs BASE_COST
CLAIMED_RATE = 67_452_592            # units/s, BENCHMARKS.md


def read_costs(path):
    """n -> (steps, variable, base, total)"""
    out = {}
    with open(path) as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) < 5:
                continue
            out[int(row[0])] = tuple(int(x) for x in row[1:5])
    return out


def read_times(path):
    """n -> {phase: [wall, ...]}"""
    out = {}
    with open(path) as f:
        for row in csv.reader(f, delimiter="\t"):
            if len(row) < 5 or row[4] != "0":
                continue
            out.setdefault(int(row[0]), {}).setdefault(row[2], []).append(float(row[3]))
    return out


def ols(xs, ys):
    """Least squares y = a + b x with standard errors on both."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    b = sxy / sxx
    a = my - b * mx
    resid = [y - (a + b * x) for x, y in zip(xs, ys)]
    if n > 2:
        s2 = sum(r * r for r in resid) / (n - 2)
        se_b = math.sqrt(s2 / sxx)
        se_a = math.sqrt(s2 * (1.0 / n + mx * mx / sxx))
    else:
        se_a = se_b = float("nan")
    return a, b, se_a, se_b, resid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="data/gpu_bench")
    ap.add_argument("--startup", type=float, default=None,
                    help="measured process-startup seconds to subtract from the "
                         "time floor before converting it to cost units")
    args = ap.parse_args()

    costs = read_costs(os.path.join(args.dir, "bench_costs.tsv"))
    times = read_times(os.path.join(args.dir, "bench_times.tsv"))

    rows = []
    for n in sorted(times):
        if n not in costs:
            continue
        warm = times[n].get("warm", [])
        if not warm:
            continue
        steps, variable, base, total = costs[n]
        rows.append({
            "n": n, "steps": steps, "variable": variable, "base": base,
            "total": total, "reps": len(warm),
            "mean": st.mean(warm), "min": min(warm), "max": max(warm),
            "sd": st.stdev(warm) if len(warm) > 1 else 0.0,
        })

    if len(rows) < 3:
        raise SystemExit(f"need >=3 sizes with warm proves, got {len(rows)}")

    print(f"{'n':>9} {'VARIABLE':>14} {'TOTAL':>14} {'reps':>4} "
          f"{'mean_s':>8} {'sd_s':>6} {'min_s':>8} {'max_s':>8}")
    for r in rows:
        print(f"{r['n']:>9} {r['variable']:>14,} {r['total']:>14,} {r['reps']:>4} "
              f"{r['mean']:>8.2f} {r['sd']:>6.2f} {r['min']:>8.2f} {r['max']:>8.2f}")

    # The fit is against VARIABLE, not TOTAL: TOTAL already folds in the
    # constant the whole exercise is trying to re-derive, so fitting against it
    # would bake the claim into the answer.
    xs = [r["variable"] for r in rows]
    ys = [r["mean"] for r in rows]
    a, b, se_a, se_b, resid = ols(xs, ys)
    rate, se_rate = 1.0 / b, se_b / (b * b)

    print()
    print("=== least-squares fit: time = floor + VARIABLE / rate ===")
    print(f"  sizes            {len(rows)}  ({min(xs):,} .. {max(xs):,} variable units)")
    print(f"  floor            {a:8.3f} s   +/- {se_a:.3f} (1 s.e.)")
    print(f"  rate           {rate:12,.0f} units/s +/- {se_rate:,.0f}")
    print(f"  residual rms     {math.sqrt(sum(r*r for r in resid)/len(resid)):.3f} s")
    print(f"  residual range   {min(resid):+.3f} .. {max(resid):+.3f} s")
    print(f"  claimed rate   {CLAIMED_RATE:12,} units/s "
          f"({100*(rate-CLAIMED_RATE)/CLAIMED_RATE:+.1f}%)")

    print()
    print("=== the floor, in cost units ===")
    print(f"  claimed BASE_COST         {CLAIMED_BASE_COST:>14,} units")
    print(f"  fitted time floor x rate  {a*rate:>14,.0f} units  "
          "(includes process startup + GPU allocation)")
    if args.startup is not None:
        proving = a - args.startup
        print(f"  measured startup          {args.startup:>14.3f} s")
        print(f"  floor minus startup       {proving:>14.3f} s "
              f"-> {proving*rate:,.0f} units of actual proving work")
        print(f"  vs claimed BASE_COST      {100*(proving*rate-CLAIMED_BASE_COST)/CLAIMED_BASE_COST:+.1f}%")

    print()
    print("=== residual scan for AIR-instance quantisation ===")
    print(f"{'n':>9} {'VARIABLE':>14} {'mean_s':>8} {'resid_s':>9} {'sd_s':>6}")
    for r, e in zip(rows, resid):
        flag = "  <-- step?" if abs(e) > 3 * max(r["sd"], 0.05) else ""
        print(f"{r['n']:>9} {r['variable']:>14,} {r['mean']:>8.2f} {e:>+9.3f} "
              f"{r['sd']:>6.2f}{flag}")

    # A staircase shows up as consecutive sizes with equal time then a jump.
    print()
    print("=== consecutive deltas (a flat run then a jump means quantisation) ===")
    print(f"{'n_lo':>9} {'n_hi':>9} {'d_VARIABLE':>14} {'d_time_s':>9} {'implied_rate':>14}")
    for lo, hi in zip(rows, rows[1:]):
        dv = hi["variable"] - lo["variable"]
        dt = hi["mean"] - lo["mean"]
        impl = dv / dt if dt > 1e-9 else float("inf")
        print(f"{lo['n']:>9} {hi['n']:>9} {dv:>14,} {dt:>+9.3f} {impl:>14,.0f}")


if __name__ == "__main__":
    main()
