// What an epoch's status is allowed to say: the vocabulary, the rule that
// checks a status against the proof beside it, and the rule that decides an
// epoch was left open for ever.
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
// anything a later daemon invents are the daemon's to say. `stranded` is the
// one status the daemon never sends, because it is a statement about a daemon
// that stopped sending anything — see `isStranded`.
export function statusForProof(declared: unknown, proof: any): string | undefined {
  if (typeof declared !== "string") return undefined;
  if (declared !== "proven") return declared;
  return proofAvailable(proof) ? "proven" : "unproven";
}

// Statuses an epoch never leaves. A consumer may cache one of these for ever
// and stop polling; anything else is still moving and has to be asked again.
const SETTLED = new Set(["proven", "unproven", "abandoned", "stranded"]);

export function isSettled(status: unknown): boolean {
  return typeof status === "string" && SETTLED.has(status);
}

// Whether an epoch still marked `proving` is one nothing will ever finish.
//
// `highestEpoch` is the highest epoch this index has ever heard about at all —
// MAX(epoch) over the whole table, not the highest one that proved. Any epoch
// below it that is still open was left behind, and this is a proof rather than
// a guess, because of how the daemon walks the chain:
//
//   `Orchestrator::tick_once` either drives the pipeline on `cursor_epoch` or
//   advances the accumulator to `cursor_epoch + 1`, never both, and it only
//   advances once `needs_justification()` is false — which is to say once
//   `attempted_epoch == cursor_epoch`, set when the epoch closed or when the
//   daemon gave up on it. `StoreState::advance` refuses any move that is not
//   exactly `cursor + 1`. So the daemon holds exactly one epoch open at a time
//   and opens them in strictly increasing order, and the first event ever
//   tagged with epoch N+1 — the `epoch_diff` stage that moves the accumulator
//   onto it — cannot be emitted until epoch N is settled.
//
// **That last sentence is false and cost a false positive.** When the daemon is
// behind the head it speculates: it proves epoch N+1's `epoch_diff` and
// `committee` during epoch N and publishes their stage timings, so N+1 exists in
// this table while N is still open. Observed on 2026-08-19 with no restart
// involved — 469657 carried two stages while 469656 was proving with three, and
// 469656 was reaped while a healthy daemon was actively working on it. It is
// sound at the head, where speculation cannot fire because the boundary state of
// N+1 does not exist yet, and unsound during catch-up — which is exactly when an
// operator needs to trust it.
//
// So the daemon's own word is the exemption: `currentEpoch` is what `/v1/status`
// reports it is working on, and that epoch is never stranded however many later
// ones exist. If the daemon dies its last epoch stops being reapable, which is
// the boundary that already existed — nothing can outlive the newest epoch —
// and `service.stale` on `/v1/status` is what says so.
//
// The tempting weaker rule is "below the highest *proven* epoch". It is weaker
// twice over: it misses an epoch stranded under a newer one that is itself
// still proving, and it goes on missing it for as long as the newer one takes.
// Nothing is gained for the caution, because the evidence that matters is that
// the daemon moved on, not that it succeeded afterwards.
//
// The one assumption is that the cursor only ever moves forward. The store
// enforces that within a run, and a fresh init point is always taken ahead of
// where the last one stopped — that is what makes it a recovery. Rewinding an
// index onto a lower epoch is `POST /v1/ingest/reset` and nothing else.
export function isStranded(
  status: unknown,
  epoch: number,
  highestEpoch: number,
  currentEpoch?: number | null,
): boolean {
  if (typeof currentEpoch === "number" && epoch === currentEpoch) return false;
  return status === "proving" && epoch < highestEpoch;
}
