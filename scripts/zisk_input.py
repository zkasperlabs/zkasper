#!/usr/bin/env python3
"""Frame a witness file as Zisk emulator input.

Zisk stdin is a sequence of length-prefixed records, and the emulator rejects an
input whose total size is not a multiple of 8. Both are easy to get wrong by
hand, so witness files stay raw on disk and get framed here.

Usage: scripts/zisk_input.py <witness.bin> <output.bin>
"""
import struct
import sys

if len(sys.argv) != 3:
    sys.exit(__doc__)

with open(sys.argv[1], "rb") as f:
    payload = f.read()

blob = struct.pack("<Q", len(payload)) + payload
blob += b"\x00" * (-len(blob) % 8)

with open(sys.argv[2], "wb") as f:
    f.write(blob)

print(f"{sys.argv[1]}: {len(payload)} bytes -> {sys.argv[2]}: {len(blob)} bytes")
