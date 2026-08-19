#!/usr/bin/env python3
"""Stage `n` real child proofs as one Zisk input for the recursion bench guest.

Usage: scripts/recursion_bench_input.py <out.bin> <n> <proof.bin> [proof.bin ...]

The guest reads `[n][len_0][proof_0]..`, so the payload is that, and the file is
the payload framed the way Zisk stdin wants it: one 8-byte length prefix, padded
to a multiple of 8.
"""
import struct
import sys

if len(sys.argv) < 4:
    sys.exit(__doc__)

out, n = sys.argv[1], int(sys.argv[2])
sources = sys.argv[3:]

payload = struct.pack("<Q", n)
for i in range(n):
    with open(sources[i % len(sources)], "rb") as f:
        proof = f.read()
    assert len(proof) % 8 == 0, f"{sources[i % len(sources)]} is not a whole number of words"
    payload += struct.pack("<Q", len(proof) // 8) + proof

blob = struct.pack("<Q", len(payload)) + payload
blob += b"\x00" * (-len(blob) % 8)
with open(out, "wb") as f:
    f.write(blob)
print(f"{out}: n={n}, {len(blob)} bytes")
