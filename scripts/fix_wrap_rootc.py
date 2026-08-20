#!/usr/bin/env python3
"""Rewrite a v1.1.0-alpha PLONK wrap's `rootc` to the verkey it was proved under.

`zisk_common::snark_publics_hash` documents `rootc` as "the verkey STAMPED into
the RecursiveF proof ... NOT generally equal to the program VK", but
`backend.plonk()` fills it from `publics_full[..4]`, which is the guest program
key. A wrap whose RecursiveF verkey is the `vadcop_final` one -- the only kind
that verifies, see `docs/zisk-verkey-override.patch` -- therefore ships a
`rootc` that disagrees with its own proof, and snarkjs rejects it.

The stored value equals the program VK, which is also the last four words of
the file (`Proof.program_vk.vk`), so the field is found without being told what
to look for. Every word of both keys exceeds 2^32, so each encodes as nine
bytes and the rewrite is length-preserving.

Usage: scripts/fix_wrap_rootc.py <wrap.bin> <out.bin> <w0> <w1> <w2> <w3>
"""
import sys

VK_LEN = 4
WORD = 9  # bincode varint: 0xfd + 8 little-endian bytes


def main():
    if len(sys.argv) != 3 + VK_LEN:
        sys.exit(__doc__)
    blob = open(sys.argv[1], "rb").read()
    verkey = [int(x, 0) for x in sys.argv[3:]]
    new = b"".join(b"\xfd" + v.to_bytes(8, "little") for v in verkey)

    # Tail: [len=4][program_vk.vk][hash_mode].
    tail = len(blob) - 1 - VK_LEN * WORD
    if blob[tail - 1] != VK_LEN:
        sys.exit("tail is not a 4-word program_vk; not a v1.1.0-alpha wrap?")
    old = blob[tail : tail + VK_LEN * WORD]

    at = [i for i in range(len(blob) - len(old) + 1)
          if blob[i : i + len(old)] == old
          and blob[i - 1] == VK_LEN and blob[i + len(old)] == VK_LEN]
    if len(at) != 1:
        sys.exit(f"expected one rootc between publics_full and program_vk, found {at}")

    with open(sys.argv[2], "wb") as f:
        f.write(blob[: at[0]] + new + blob[at[0] + len(old) :])
    print(f"{sys.argv[1]}: rootc at {at[0]} -> {sys.argv[2]}")


main()
