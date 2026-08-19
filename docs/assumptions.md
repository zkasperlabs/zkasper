# Moved — this page was split

The finality proof and the fast confirmation rule are two products with two
threat models, two thresholds and two sets of circuits. Holding their
assumptions on one page kept producing conclusions carried across from the wrong
one, so the page was split three ways.

- [finality/assumptions.md](finality/assumptions.md) — what a finalization proof
  trusts, and the risks accepted in it. Includes "Is the shuffle necessary? Yes
  to compute, no to prove".
- [fcr/assumptions.md](fcr/assumptions.md) — what a fast confirmation proof
  would trust. FCR does not use the committee proof.
- [shared/assumptions.md](shared/assumptions.md) — the accumulator, the init
  point, the BLS arithmetic, native mode and the on-chain wrap: what both rest
  on, stated once.

Read a product's page **and** the shared page. Neither is complete alone.
[README.md](README.md) is the map.
