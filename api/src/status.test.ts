// The API's own refusal to store a status it can see is false.
//
//   node --test src/status.test.ts        (from api/, no install needed)
//
// Node 22 strips the types, so this runs with no toolchain at all. The rest of
// the worker needs a Workers runtime to test; this one rule does not, and it is
// the rule that keeps a `proven` epoch with no proof out of the index.

import { test } from "node:test";
import assert from "node:assert/strict";

import { proofAvailable, statusForProof } from "./status.ts";

// Exactly what mainnet 469539 carried on 2026-08-19: a whole proof reference,
// a program, a verification key, committed public bytes — and no proof.
const empty = {
  stage: "stream_final",
  available: false,
  bytes: 0,
  words: 0,
  sha256: null,
  program: "zkasper-stream-final-guest",
  program_vk: "0x3fe7629b91974a505a2e7fc5242c4c9ecef7fc87740047ec2115b4b0a3c3c00a",
};

const real = { ...empty, available: true, bytes: 254624, words: 31828, sha256: "0xca98" };

test("a daemon claiming proven over no proof is stored as unproven", () => {
  assert.equal(statusForProof("proven", empty), "unproven");
});

test("a proof with bytes is still proven", () => {
  assert.equal(statusForProof("proven", real), "proven");
});

test("no proof at all cannot be proven", () => {
  for (const p of [null, undefined, {}, "0xdeadbeef", 254624]) {
    assert.equal(statusForProof("proven", p), "unproven", `proof: ${JSON.stringify(p)}`);
  }
});

// Either field alone is a claim about the other, so neither is taken on its own.
test("available and bytes have to agree", () => {
  assert.equal(proofAvailable({ available: true, bytes: 0 }), false);
  assert.equal(proofAvailable({ available: false, bytes: 254624 }), false);
  assert.equal(proofAvailable({ available: true, bytes: "254624" }), false);
  assert.equal(proofAvailable({ available: true, bytes: 254624 }), true);
});

test("every other status is the daemon's to say", () => {
  assert.equal(statusForProof("proving", empty), "proving");
  assert.equal(statusForProof("abandoned", empty), "abandoned");
  assert.equal(statusForProof(undefined, real), undefined);
  assert.equal(statusForProof(7, real), undefined);
});
