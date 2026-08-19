// The API's own refusal to store a status it can see is false.
//
//   node --test src/status.test.ts        (from api/, no install needed)
//
// Node 22 strips the types, so this runs with no toolchain at all. The rest of
// the worker needs a Workers runtime to test; this one rule does not, and it is
// the rule that keeps a `proven` epoch with no proof out of the index.

import { test } from "node:test";
import assert from "node:assert/strict";

import { isSettled, isStranded, proofAvailable, statusForProof } from "./status.ts";

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

// ---------------------------------------------------------------- stranded

// The real thing, from mainnet on 2026-08-19: 124 proven, 4 abandoned, 2
// unproven, and 14 epochs still calling themselves `proving` — of which
// thirteen were opened by daemons that died or were redeployed mid-epoch, and
// one was the epoch actually being proved at the time.
const STRANDED = [
  469421, 469429, 469436, 469441, 469451, 469469, 469470,
  469569, 469570, 469571, 469572, 469597, 469598,
];
const IN_FLIGHT = 469624;

test("an epoch a later one outlived is stranded", () => {
  for (const epoch of STRANDED) {
    assert.equal(isStranded("proving", epoch, IN_FLIGHT), true, `epoch ${epoch}`);
  }
});

// The one thing this rule is not allowed to get wrong. The daemon holds one
// epoch open at a time, so the highest epoch the index knows about is the only
// one that can still be in flight — and it is never below itself.
test("the epoch actually being proved is not stranded", () => {
  assert.equal(isStranded("proving", IN_FLIGHT, IN_FLIGHT), false);
});

test("an epoch opened before anything newer arrived is not stranded", () => {
  // The first epoch of a run, on the batch that opened it: it is the high-water
  // mark, and stays in flight until the daemon reaches the next one.
  assert.equal(isStranded("proving", 469599, 469599), false);
});

// Stranded is a statement about an epoch nobody closed. An epoch that reached
// an outcome has one, and keeps it however far the daemon has since walked.
test("only an open epoch can be stranded", () => {
  for (const s of ["proven", "unproven", "abandoned", "stranded", null, undefined, ""]) {
    assert.equal(isStranded(s, 469421, IN_FLIGHT), false, `status: ${s}`);
  }
});

// What a consumer is allowed to stop polling, which is also what the epoch
// route caches for a day. A status missing from here is one that gets served
// with a 5-second cache for ever.
test("stranded is settled and proving is not", () => {
  for (const s of ["proven", "unproven", "abandoned", "stranded"]) {
    assert.equal(isSettled(s), true, `status: ${s}`);
  }
  for (const s of ["proving", "", null, undefined, 7]) {
    assert.equal(isSettled(s), false, `status: ${s}`);
  }
});

test("stranded is the api's word, so a daemon that sent it still passes through", () => {
  assert.equal(statusForProof("stranded", empty), "stranded");
});
