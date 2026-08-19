#!/usr/bin/env python3
"""Turn a `cargo-zisk prove` / `wrap` proof file into the word layout a guest verifies.

`cargo-zisk` writes a bincode-serialized `Proof`; `verify_zisk_proof` wants
`Proof::get_proof_u64()`, which is
`[minimal][n_publics][flag? | program_vk(4) | publics(64)][proof..][zisk_vk(4)]`.
The host prover in this repo calls `get_proof_u64` itself, so this script exists
only so a proof made by the CLI can be handed to a guest without linking the SDK.

Usage: scripts/zisk_proof_words.py <proof.bin> <out.words.bin>
"""
import struct
import sys


class Reader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def u8(self):
        v = self.d[self.i]
        self.i += 1
        return v

    def varint(self):
        # bincode 2 "standard": <251 inline, 251->u16, 252->u32, 253->u64, 254->u128
        b = self.u8()
        if b < 251:
            return b
        width = {251: 2, 252: 4, 253: 8, 254: 16}[b]
        v = int.from_bytes(self.d[self.i:self.i + width], "little")
        self.i += width
        return v

    def vec_u64(self):
        return [self.varint() for _ in range(self.varint())]

    def string(self):
        n = self.varint()
        s = self.d[self.i:self.i + n].decode()
        self.i += n
        return s


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    r = Reader(open(sys.argv[1], "rb").read())

    body = r.varint()
    assert body == 0, f"not a Vadcop proof body (variant {body})"
    proof = r.vec_u64()
    zisk_vk = r.vec_u64()
    kind = r.varint()          # 0 Final, 1 Recurser, 2 Minimal
    hash_family = r.string()
    publics_full = r.vec_u64()

    flag = {0: [1], 1: [0], 2: []}[kind]
    stark_publics = flag + publics_full
    words = [1 if kind == 2 else 0, len(stark_publics)] + stark_publics + proof + zisk_vk

    with open(sys.argv[2], "wb") as f:
        f.write(struct.pack("<%dQ" % len(words), *words))
    print(
        f"{sys.argv[1]}: kind={['Final', 'Recurser', 'Minimal'][kind]} hash={hash_family} "
        f"proof={len(proof)} publics={len(publics_full)} vk={len(zisk_vk)} "
        f"-> {sys.argv[2]}: {len(words)} words"
    )


main()
