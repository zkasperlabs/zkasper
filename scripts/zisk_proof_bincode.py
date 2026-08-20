#!/usr/bin/env python3
"""Turn a published proof back into the file `cargo-zisk verify` reads.

The inverse of `zisk_proof_words.py`. `/v1/proofs/<epoch>` serves the flat word
vector `Proof::get_proof_u64()` hands out, which is what
`zkasper_common::recursion::verify_child` wants and what every recursive edge in
the pipeline passes around. `cargo-zisk verify -p` wants a bincode-serialized
`zisk_common::Proof` instead, and panics with `Expected 68 u64 publics, got 0`
on the word form. Neither the SDK nor the CLI rebuilds one from words.

Rebuilding it costs one thing the words do not carry: the hash family, which is
a constant of the Zisk release (`Poseidon1` for v1.1.0-alpha) rather than of the
proof, and is what `zisklib::verify_zisk_proof` passes to the verifier.

`cargo-zisk verify` on the result is a *second* verifier, not the same one twice
-- but it is a weaker check than `verify_child`. It reads the vadcop_final key
out of the proof's own tail and verifies against that, so it says "a valid proof
of some circuit" and never "of this one". Pin the key yourself; see
`crates/common/src/recursion.rs`.

Usage: scripts/zisk_proof_bincode.py <proof.words.bin> <out.bin>
"""
import struct
import sys

HASH_FAMILY = "Poseidon1"
HASH_MODE_POSEIDON1 = 0
PROGRAM_VK_LEN = 4


def varint(v):
    if v < 251:
        return bytes([v])
    for tag, width in ((251, 2), (252, 4), (253, 8), (254, 16)):
        if v < 1 << (width * 8):
            return bytes([tag]) + v.to_bytes(width, "little")
    raise ValueError(v)


def vec_u64(xs):
    return varint(len(xs)) + b"".join(varint(x) for x in xs)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    raw = open(sys.argv[1], "rb").read()
    if len(raw) % 8:
        sys.exit("not a whole number of u64 words")
    w = list(struct.unpack("<%dQ" % (len(raw) // 8), raw))

    minimal, n_publics = w[0], w[1]
    if minimal not in (0, 1):
        sys.exit("first word is not the minimal flag")
    stark_publics = w[2 : 2 + n_publics]
    if len(stark_publics) != n_publics:
        sys.exit("truncated publics")
    proof = w[2 + n_publics : -4]
    zisk_vk = w[-4:]
    if not proof:
        sys.exit("no proof body between the publics and the key")

    if minimal:
        kind, publics_full = 2, stark_publics
    else:
        # Index 0 is `is_vadcop_final_proof`: 1 for a leaf, 0 for an aggregated
        # recurser proof. `Proof` carries the distinction as its kind and drops
        # the word, so the two forms round-trip through different tags.
        kind = {1: 0, 0: 1}[stark_publics[0]]
        publics_full = stark_publics[1:]

    out = (
        varint(0)  # ProofBody::Vadcop
        + vec_u64(proof)
        + vec_u64(zisk_vk)
        + varint(kind)
        + varint(len(HASH_FAMILY))
        + HASH_FAMILY.encode()
        + vec_u64(publics_full)
        # `Proof.program_vk`, a `ProgramVK { vk, hash_mode }`. The words are the
        # first four of `publics_full` again -- the struct is what a caller reads
        # a proof's program key off, and the body is where it was committed.
        + vec_u64(publics_full[:PROGRAM_VK_LEN])
        + varint(HASH_MODE_POSEIDON1)
    )
    with open(sys.argv[2], "wb") as f:
        f.write(out)
    print(
        f"{sys.argv[1]}: {len(w)} words kind={['Final', 'Recurser', 'Minimal'][kind]} "
        f"proof={len(proof)} publics={len(publics_full)} -> {sys.argv[2]}: {len(out)} bytes"
    )


main()
