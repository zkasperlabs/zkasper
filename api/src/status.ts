// What an epoch's status is allowed to say, checked against the proof beside it.
//
// Split out of index-do.ts only so it can be tested without a Workers runtime:
// this file imports nothing, so `node --test src/status.test.ts` runs it.

// Whether a proof reference is one a consumer can actually fetch. Both fields
// are required to agree, because either one alone is a claim about the other.
export function proofAvailable(p: any): boolean {
  if (!p || typeof p !== "object") return false;
  return p.available === true && typeof p.bytes === "number" && p.bytes > 0;
}

// `proven` means proof bytes exist, and nothing else.
//
// The daemon decides an epoch's status and this worker derives none of it, but
// it does refuse one thing: a record that contradicts itself. A summary that
// says `proven` over a proof with no bytes is stored as `unproven`, whatever
// the daemon called it.
//
// This is the fault nobody downstream can catch. A consumer asks for the proof,
// gets nothing, and cannot tell a service that is lying from a mistake of their
// own — so it is checked at both ends and trusted at neither. Mainnet 469538
// and 469539 published as `proven` with zero bytes on 2026-08-19 because it was
// checked at neither.
//
// Any other status passes through untouched: `proving`, `abandoned` and
// anything a later daemon invents are the daemon's to say.
export function statusForProof(declared: unknown, proof: any): string | undefined {
  if (typeof declared !== "string") return undefined;
  if (declared !== "proven") return declared;
  return proofAvailable(proof) ? "proven" : "unproven";
}
