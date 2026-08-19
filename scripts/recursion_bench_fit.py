#!/usr/bin/env python3
"""Least squares on a 0..3 child ladder, with residuals.

Usage: scripts/recursion_bench_fit.py <label> "n:value" ["n:value" ...]

Separating the intercept from the slope is the whole point of the ladder: a
regression on multi-child proof times alone reports whatever is not otherwise
modelled as slope.
"""
import sys


def fit(points):
    n = len(points)
    sx = sum(p[0] for p in points)
    sy = sum(p[1] for p in points)
    sxx = sum(p[0] * p[0] for p in points)
    sxy = sum(p[0] * p[1] for p in points)
    slope = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    intercept = (sy - slope * sx) / n
    return intercept, slope


label, points = sys.argv[1], []
for arg in sys.argv[2:]:
    k, v = arg.split(":")
    points.append((float(k), float(v)))

intercept, slope = fit(points)
print(f"{label}: intercept {intercept:,.4f}  slope {slope:,.4f} per child")
worst = 0.0
for k, v in points:
    r = v - (intercept + slope * k)
    worst = max(worst, abs(r))
    print(f"  n={k:.0f}  measured {v:,.4f}  fit {intercept + slope * k:,.4f}  residual {r:+,.4f}")
print(f"  worst residual {worst:,.4f} = {100 * worst / slope:.4f}% of one child")
