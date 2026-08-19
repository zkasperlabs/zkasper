#!/usr/bin/env python3
"""Fit the GPU ladders and report throughput, for the recursion cost measurement."""

RUNS = {
    "minimal run1": [3.616, 46.230, 90.981, 143.340],
    "minimal run2": [2.376, 43.245, 87.039, 142.129],
    "non-minimal run1": [2.373, 4.661, 6.269, 7.906],
    "non-minimal run2": [2.349, 4.736, 6.175, 7.694],
}
MIN_UNITS = [314102, 24933600635, 49868233412, 74801519283]
NM_UNITS = [314102, 1079099782, 2157884800, 3236669818]


def fit(points):
    n = len(points)
    sx = sum(p[0] for p in points)
    sy = sum(p[1] for p in points)
    sxx = sum(p[0] ** 2 for p in points)
    sxy = sum(p[0] * p[1] for p in points)
    slope = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    return (sy - slope * sx) / n, slope


for name, seconds in RUNS.items():
    units = NM_UNITS if "non" in name else MIN_UNITS
    marginals = [round(seconds[i + 1] - seconds[i], 3) for i in range(3)]
    print(f"{name}: {seconds}  marginals {marginals}")
    for i in range(1, 4):
        rate = (units[i] - units[0]) / (seconds[i] - seconds[0]) / 1e6
        print(f"   n={i}  {rate:,.0f} M units/s")

print()
for name, keys in [
    ("minimal, both runs", ["minimal run1", "minimal run2"]),
    ("non-minimal, both runs", ["non-minimal run1", "non-minimal run2"]),
]:
    points = [(i, RUNS[k][i]) for k in keys for i in range(4)]
    intercept, slope = fit(points)
    worst = max(abs(y - (intercept + slope * x)) for x, y in points)
    print(
        f"{name}: intercept {intercept:.3f} s  slope {slope:.3f} s/child  "
        f"worst residual {worst:.3f} s = {100 * worst / slope:.1f}% of a child"
    )

print()
one_min = RUNS["minimal run2"][1] - RUNS["minimal run2"][0]
one_nm = RUNS["non-minimal run2"][1] - RUNS["non-minimal run2"][0]
print(f"one child, warm, n=1 minus n=0: minimal {one_min:.3f} s, non-minimal {one_nm:.3f} s, ratio {one_min / one_nm:.1f}x")
