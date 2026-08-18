// IndexDO: the single writer for the zkasper index. Holds the epoch/stage index,
// the SSE ring buffer, and (when no R2 bucket is bound) the proof blobs themselves.
// There is exactly one daemon, so one object is the whole store.
import { DurableObject } from "cloudflare:workers";

const RING_EVENTS = 5000;
const MAX_STREAMS = 200;
const KEEPALIVE_MS = 15_000;
const STALE_MS = 120_000;
const CHUNK_BYTES = 512 * 1024;
const INLINE_TOTAL_CAP = 1024 * 1024 * 1024;

type Row = Record<string, any>;

interface Sub {
  writer: WritableStreamDefaultWriter<Uint8Array>;
  chain: Promise<unknown>;
  dead: boolean;
}

const enc = new TextEncoder();

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  const h = new Headers(init.headers);
  h.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(body), { ...init, headers: h });
}

function err(status: number, error: string, message: string): Response {
  return jsonResponse({ error, message }, { status });
}

function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

function jparse(s: unknown): any {
  if (typeof s !== "string" || s.length === 0) return null;
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

// attesting_balance / total_active_balance are u64 strings; never touch them as numbers.
function pct(attesting: unknown, total: unknown): number | null {
  if (typeof attesting !== "string" || typeof total !== "string") return null;
  try {
    const t = BigInt(total);
    if (t === 0n) return null;
    return Number((BigInt(attesting) * 1000000n) / t) / 10000;
  } catch {
    return null;
  }
}

export class IndexDO extends DurableObject {
  private sql: SqlStorage;
  private subs = new Set<Sub>();
  private keepalive: any = null;
  private nextSeq = 1;

  constructor(ctx: DurableObjectState, env: any) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.migrate();
      this.nextSeq = this.loadSeq();
    });
  }

  private migrate(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS kv (
        k TEXT PRIMARY KEY,
        v TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY,
        daemon_id TEXT NOT NULL,
        daemon_seq INTEGER NOT NULL,
        type TEXT NOT NULL,
        epoch INTEGER,
        unix_millis INTEGER NOT NULL,
        received_millis INTEGER NOT NULL,
        data TEXT NOT NULL,
        UNIQUE (daemon_id, daemon_seq)
      );
      CREATE TABLE IF NOT EXISTS epochs (
        epoch INTEGER PRIMARY KEY,
        chain TEXT,
        status TEXT NOT NULL DEFAULT 'proving',
        abandoned_reason TEXT,
        target_root TEXT,
        pipeline TEXT,
        prover TEXT,
        opened_unix_millis INTEGER,
        closed_unix_millis INTEGER,
        finalizes_epoch INTEGER,
        justified TEXT,
        finalized TEXT,
        accumulator TEXT,
        latency TEXT,
        proof TEXT,
        public_inputs TEXT,
        verify TEXT,
        summary TEXT,
        stage_count INTEGER,
        prove_millis_total INTEGER,
        wall_millis_total INTEGER,
        updated_millis INTEGER
      );
      CREATE TABLE IF NOT EXISTS stages (
        epoch INTEGER NOT NULL,
        stage TEXT NOT NULL,
        idx INTEGER NOT NULL,
        slot INTEGER,
        started_unix_millis INTEGER,
        finished_unix_millis INTEGER,
        millis INTEGER,
        prove_millis INTEGER,
        wrap_millis INTEGER,
        witness TEXT,
        proof_bytes INTEGER,
        extra TEXT,
        PRIMARY KEY (epoch, stage, idx)
      );
      CREATE TABLE IF NOT EXISTS proofs (
        epoch INTEGER PRIMARY KEY,
        backend TEXT NOT NULL,
        bytes INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        stage TEXT,
        program_vk TEXT,
        public_bytes TEXT,
        chunks INTEGER NOT NULL DEFAULT 0,
        stored_millis INTEGER NOT NULL,
        evicted INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS proof_chunks (
        epoch INTEGER NOT NULL,
        n INTEGER NOT NULL,
        data BLOB NOT NULL,
        PRIMARY KEY (epoch, n)
      );
      CREATE INDEX IF NOT EXISTS events_epoch ON events (epoch);
    `);
  }

  private loadSeq(): number {
    const kv = num(this.getKvNum("stream_seq")) ?? 0;
    const max = num(this.one("SELECT MAX(seq) AS m FROM events")?.m) ?? 0;
    return Math.max(kv, max) + 1;
  }

  private one(q: string, ...b: any[]): Row | null {
    const rows = this.sql.exec(q, ...b).toArray();
    return rows.length ? (rows[0] as Row) : null;
  }

  private all(q: string, ...b: any[]): Row[] {
    return this.sql.exec(q, ...b).toArray() as Row[];
  }

  private getKv(k: string): string | null {
    const r = this.one("SELECT v FROM kv WHERE k = ?", k);
    return r ? (r.v as string) : null;
  }

  private getKvNum(k: string): number | null {
    const v = this.getKv(k);
    return v === null ? null : Number(v);
  }

  private setKv(k: string, v: string): void {
    this.sql.exec("INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v", k, v);
  }

  // ---------------------------------------------------------------- routing

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const p = url.pathname;
    try {
      if (p === "/do/ingest") return await this.ingest(request);
      if (p === "/do/reset") return this.reset();
      if (p === "/do/status") return this.serveStatus();
      if (p === "/do/epochs") return this.serveEpochs(url);
      if (p.startsWith("/do/epoch/")) return this.serveEpoch(Number(p.slice("/do/epoch/".length)));
      if (p.startsWith("/do/proof-meta/")) return this.serveProofMeta(Number(p.slice("/do/proof-meta/".length)));
      if (p.startsWith("/do/proof-body/")) return this.serveProofBody(Number(p.slice("/do/proof-body/".length)));
      if (p.startsWith("/do/proof-inline/")) return await this.putProofInline(request, Number(p.slice("/do/proof-inline/".length)));
      if (p.startsWith("/do/proof-meta-put/")) return await this.putProofMeta(request, Number(p.slice("/do/proof-meta-put/".length)));
      if (p === "/do/cursor") return this.serveCursor();
      if (p === "/do/live") return this.serveLive(request, url);
      return err(404, "not_found", "no such internal route");
    } catch (e: any) {
      return err(500, "internal", String(e && e.message ? e.message : e));
    }
  }

  // ---------------------------------------------------------------- ingest

  private async ingest(request: Request): Promise<Response> {
    const body = await request.json<any>();
    const now = Date.now();
    const daemon = body && typeof body.daemon === "object" && body.daemon ? body.daemon : {};
    const daemonId = typeof daemon.id === "string" && daemon.id ? daemon.id : "unknown";
    if (Object.keys(daemon).length > 0) this.setKv("daemon", JSON.stringify(daemon));

    const events: any[] = Array.isArray(body?.events) ? body.events : [];
    let accepted = 0;
    let duplicates = 0;
    let lastDaemonSeq = this.getKvNum("last_daemon_seq") ?? 0;
    const outgoing: Array<{ seq: number; type: string; data: any }> = [];

    for (const ev of events) {
      if (!ev || typeof ev !== "object" || typeof ev.type !== "string") continue;
      const dseq = num(ev.seq);
      if (dseq === null) continue;
      const r = this.record(daemonId, dseq, ev.type, ev, now);
      if (r === null) {
        duplicates++;
        continue;
      }
      accepted++;
      if (dseq > lastDaemonSeq) lastDaemonSeq = dseq;
      this.apply(ev.type, r.data);
      outgoing.push({ seq: r.seq, type: ev.type, data: r.data });
    }

    // The daemon may carry status as a top-level field rather than as an event.
    // Synthesize one status event in that case so SSE clients see it too; keyed
    // on the batch's last seq so a replayed spool does not duplicate it.
    const status = body?.status;
    if (status && typeof status === "object") {
      this.setKv("status", JSON.stringify(status));
      this.setKv("status_received_millis", String(now));
      if (!events.some((e) => e && e.type === "status")) {
        // Keyed on updated_unix so a status-only tick still fans out while a
        // replayed spool of the same snapshots stays a no-op.
        const key = num(status.updated_unix) ?? lastDaemonSeq;
        const r = this.record(daemonId + "#status", key, "status", { type: "status", seq: key, unix_millis: now, status }, now);
        if (r !== null) outgoing.push({ seq: r.seq, type: "status", data: r.data });
      }
    }

    this.setKv("last_daemon_seq", String(lastDaemonSeq));
    this.setKv("stream_seq", String(this.nextSeq - 1));
    this.trim();

    for (const o of outgoing) this.broadcast(o.seq, o.type, o.data);

    return jsonResponse({ ok: true, accepted, duplicates, last_seq: lastDaemonSeq });
  }

  // Returns null when the (daemon_id, daemon_seq) pair was already stored.
  private record(daemonId: string, daemonSeq: number, type: string, ev: any, now: number): { seq: number; data: any } | null {
    const seq = this.nextSeq;
    const data = { ...ev };
    delete data.type;
    data.seq = seq;
    if (num(data.unix_millis) === null) data.unix_millis = now;
    const payload = JSON.stringify(data);
    const inserted = this.sql
      .exec(
        "INSERT OR IGNORE INTO events (seq, daemon_id, daemon_seq, type, epoch, unix_millis, received_millis, data)" +
          " VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING seq",
        seq,
        daemonId,
        daemonSeq,
        type,
        num(ev.epoch),
        data.unix_millis,
        now,
        payload,
      )
      .toArray();
    if (inserted.length === 0) return null;
    this.nextSeq = seq + 1;
    return { seq, data };
  }

  private trim(): void {
    const max = num(this.one("SELECT MAX(seq) AS m FROM events")?.m);
    if (max === null) return;
    this.sql.exec("DELETE FROM events WHERE seq <= ?", max - RING_EVENTS);
  }

  // ---------------------------------------------------------------- indexing

  private touchEpoch(epoch: number): void {
    this.sql.exec("INSERT INTO epochs (epoch) VALUES (?) ON CONFLICT (epoch) DO NOTHING", epoch);
  }

  private setEpoch(epoch: number, patch: Record<string, any>): void {
    this.touchEpoch(epoch);
    const cols: string[] = [];
    const vals: any[] = [];
    for (const [k, v] of Object.entries(patch)) {
      if (v === undefined) continue;
      cols.push(`${k} = ?`);
      vals.push(v);
    }
    cols.push("updated_millis = ?");
    vals.push(Date.now());
    this.sql.exec(`UPDATE epochs SET ${cols.join(", ")} WHERE epoch = ?`, ...vals, epoch);
  }

  private mergeLatency(epoch: number, patch: Record<string, any>): void {
    const row = this.one("SELECT latency FROM epochs WHERE epoch = ?", epoch);
    const cur = jparse(row?.latency) ?? {};
    const next: Record<string, any> = { epoch, ...cur };
    for (const [k, v] of Object.entries(patch)) if (v !== undefined) next[k] = v;
    this.setEpoch(epoch, { latency: JSON.stringify(next) });
  }

  private jcol(v: unknown): string | undefined {
    return v === undefined || v === null ? undefined : JSON.stringify(v);
  }

  // The epoch.closed summary is authoritative for the fields it carries, but it
  // is a digest: merging keeps richer keys an earlier proof.landed reported
  // (elf_sha256 and friends) instead of dropping them.
  private jmerge(epoch: number, col: string, v: unknown): string | undefined {
    if (v === undefined || v === null) return undefined;
    if (typeof v !== "object" || Array.isArray(v)) return JSON.stringify(v);
    const cur = jparse(this.one(`SELECT ${col} AS c FROM epochs WHERE epoch = ?`, epoch)?.c);
    return JSON.stringify(cur && typeof cur === "object" && !Array.isArray(cur) ? { ...cur, ...v } : v);
  }

  private apply(type: string, d: any): void {
    const epoch = num(d.epoch);
    switch (type) {
      case "status": {
        if (d.status && typeof d.status === "object") {
          this.setKv("status", JSON.stringify(d.status));
          this.setKv("status_received_millis", String(Date.now()));
        }
        return;
      }
      case "epoch.opened": {
        if (epoch === null) return;
        this.setEpoch(epoch, {
          target_root: typeof d.target_root === "string" ? d.target_root : undefined,
          finalizes_epoch: num(d.finalizes_epoch) ?? undefined,
          accumulator: this.jcol(d.accumulator),
          opened_unix_millis: num(d.opened_unix_millis) ?? num(d.unix_millis) ?? undefined,
          chain: typeof d.chain === "string" ? d.chain : undefined,
          pipeline: typeof d.pipeline === "string" ? d.pipeline : undefined,
          prover: typeof d.prover === "string" ? d.prover : undefined,
        });
        const r = this.one("SELECT status FROM epochs WHERE epoch = ?", epoch);
        if (!r || r.status === null) this.setEpoch(epoch, { status: "proving" });
        return;
      }
      case "stage.started":
      case "stage.finished": {
        if (epoch === null || typeof d.stage !== "string") return;
        this.touchEpoch(epoch);
        const idx = num(d.index);
        const key = idx === null ? -1 : idx;
        this.sql.exec(
          "INSERT INTO stages (epoch, stage, idx) VALUES (?, ?, ?) ON CONFLICT (epoch, stage, idx) DO NOTHING",
          epoch,
          d.stage,
          key,
        );
        const patch: Record<string, any> = {
          slot: num(d.slot),
          witness: this.jcol(d.witness) ?? null,
        };
        if (type === "stage.started") {
          patch.started_unix_millis = num(d.started_unix_millis) ?? num(d.unix_millis);
        } else {
          patch.finished_unix_millis = num(d.finished_unix_millis) ?? num(d.unix_millis);
          patch.millis = num(d.millis);
          patch.prove_millis = num(d.prove_millis);
          patch.wrap_millis = num(d.wrap_millis);
          patch.proof_bytes = num(d.proof_bytes);
          if (num(d.started_unix_millis) !== null) patch.started_unix_millis = num(d.started_unix_millis);
        }
        const known = new Set([
          "seq",
          "unix_millis",
          "epoch",
          "stage",
          "slot",
          "index",
          "millis",
          "prove_millis",
          "wrap_millis",
          "witness",
          "proof_bytes",
          "started_unix_millis",
          "finished_unix_millis",
        ]);
        const extra: Record<string, any> = {};
        for (const [k, v] of Object.entries(d)) if (!known.has(k)) extra[k] = v;
        // COALESCE so a stage.started that arrives after its stage.finished
        // (out-of-order spool replay) never blanks a measured value.
        this.sql.exec(
          "UPDATE stages SET" +
            " slot = COALESCE(?, slot)," +
            " started_unix_millis = COALESCE(?, started_unix_millis)," +
            " finished_unix_millis = COALESCE(?, finished_unix_millis)," +
            " millis = COALESCE(?, millis)," +
            " prove_millis = COALESCE(?, prove_millis)," +
            " wrap_millis = COALESCE(?, wrap_millis)," +
            " witness = COALESCE(?, witness)," +
            " proof_bytes = COALESCE(?, proof_bytes)," +
            " extra = COALESCE(?, extra)" +
            " WHERE epoch = ? AND stage = ? AND idx = ?",
          patch.slot ?? null,
          patch.started_unix_millis ?? null,
          patch.finished_unix_millis ?? null,
          patch.millis ?? null,
          patch.prove_millis ?? null,
          patch.wrap_millis ?? null,
          patch.witness ?? null,
          patch.proof_bytes ?? null,
          Object.keys(extra).length ? JSON.stringify(extra) : null,
          epoch,
          d.stage,
          key,
        );
        return;
      }
      case "threshold.crossed": {
        if (epoch === null) return;
        this.mergeLatency(epoch, {
          threshold_unix_millis: num(d.threshold_unix_millis) ?? num(d.unix_millis) ?? undefined,
        });
        return;
      }
      case "threshold.fired": {
        if (epoch === null) return;
        this.mergeLatency(epoch, {
          fired_unix_millis: num(d.fired_unix_millis) ?? num(d.unix_millis) ?? undefined,
          wait_millis: num(d.wait_millis) ?? undefined,
          tail: num(d.tail) ?? undefined,
          tail_named: num(d.tail_named) ?? undefined,
          late_groups: num(d.late_groups) ?? undefined,
        });
        return;
      }
      case "proof.landed": {
        if (epoch === null) return;
        const patch: Record<string, any> = {
          proof: this.jcol(d.proof),
          public_inputs: this.jcol(d.public_inputs),
          verify: this.jcol(d.verify),
          status: "proven",
        };
        if (d.latency && typeof d.latency === "object") patch.latency = JSON.stringify({ epoch, ...d.latency });
        this.setEpoch(epoch, patch);
        return;
      }
      case "epoch.closed": {
        if (epoch === null) return;
        const s = d.summary && typeof d.summary === "object" ? d.summary : {};
        this.setEpoch(epoch, {
          summary: this.jcol(d.summary),
          status: typeof s.status === "string" ? s.status : undefined,
          target_root: typeof s.target_root === "string" ? s.target_root : undefined,
          pipeline: typeof s.pipeline === "string" ? s.pipeline : undefined,
          prover: typeof s.prover === "string" ? s.prover : undefined,
          chain: typeof s.chain === "string" ? s.chain : undefined,
          opened_unix_millis: num(s.opened_unix_millis) ?? undefined,
          closed_unix_millis: num(s.closed_unix_millis) ?? num(d.unix_millis) ?? undefined,
          finalizes_epoch: num(s.finalizes_epoch) ?? undefined,
          justified: this.jcol(s.justified),
          finalized: this.jcol(s.finalized),
          latency: this.jmerge(epoch, "latency", s.latency),
          proof: this.jmerge(epoch, "proof", s.proof),
          public_inputs: this.jmerge(epoch, "public_inputs", s.public_inputs),
          verify: this.jmerge(epoch, "verify", s.verify),
          accumulator: this.jmerge(epoch, "accumulator", s.accumulator),
          stage_count: num(s.stage_count) ?? undefined,
          prove_millis_total: num(s.prove_millis_total) ?? undefined,
          wall_millis_total: num(s.wall_millis_total) ?? undefined,
        });
        return;
      }
      case "epoch.abandoned": {
        if (epoch === null) return;
        this.setEpoch(epoch, {
          status: "abandoned",
          abandoned_reason: typeof d.reason === "string" ? d.reason : null,
          closed_unix_millis: num(d.closed_unix_millis) ?? num(d.unix_millis) ?? undefined,
        });
        return;
      }
      default:
        return;
    }
  }

  // ---------------------------------------------------------------- reads

  private daemonRecord(): any {
    return jparse(this.getKv("daemon")) ?? {};
  }

  private chain(): string | null {
    const st = jparse(this.getKv("status"));
    if (st && typeof st.chain === "string") return st.chain;
    const d = this.daemonRecord();
    return typeof d.chain === "string" ? d.chain : null;
  }

  private buildStatus(): any {
    const now = Date.now();
    const stored = jparse(this.getKv("status"));
    const received = this.getKvNum("status_received_millis");
    const d = this.daemonRecord();
    const counts = this.one(
      "SELECT (SELECT COUNT(*) FROM epochs) AS e," +
        " (SELECT COUNT(*) FROM proofs WHERE evicted = 0) AS p," +
        " (SELECT COALESCE(SUM(bytes), 0) FROM proofs WHERE evicted = 0) AS b",
    );
    const out: any = stored ? { ...stored } : {};
    out.version = 1;
    if (typeof out.chain !== "string") out.chain = typeof d.chain === "string" ? d.chain : null;
    if (typeof out.prover !== "string") out.prover = typeof d.prover === "string" ? d.prover : null;
    if (typeof out.pipeline !== "string") out.pipeline = typeof d.pipeline === "string" ? d.pipeline : null;
    if (out.current_epoch && typeof out.current_epoch === "object" && num(out.current_epoch.attesting_pct) === null) {
      const p = pct(out.current_epoch.attesting_balance, out.current_epoch.total_active_balance);
      if (p !== null) out.current_epoch.attesting_pct = p;
    }
    out.service = {
      received_unix_millis: received,
      age_millis: received === null ? null : now - received,
      stale: received === null ? true : now - received > STALE_MS,
      seq: this.getKvNum("last_daemon_seq") ?? 0,
      epochs_indexed: num(counts?.e) ?? 0,
      proofs_stored: num(counts?.p) ?? 0,
      proof_bytes_stored: String(num(counts?.b) ?? 0),
    };
    return out;
  }

  private serveStatus(): Response {
    return jsonResponse(this.buildStatus(), { headers: { "cache-control": "public, max-age=2" } });
  }

  private stageCount(epoch: number): number {
    return num(this.one("SELECT COUNT(*) AS c FROM stages WHERE epoch = ?", epoch)?.c) ?? 0;
  }

  private proveTotal(epoch: number): number | null {
    return num(this.one("SELECT SUM(prove_millis) AS s FROM stages WHERE epoch = ?", epoch)?.s);
  }

  private proofObject(r: Row): any {
    const p = jparse(r.proof);
    if (!p) return null;
    const out = { ...p };
    if (typeof out.url !== "string") out.url = `/v1/proofs/${r.epoch}`;
    return out;
  }

  private epochEntry(r: Row): any {
    return {
      epoch: r.epoch,
      target_root: r.target_root ?? null,
      status: r.status ?? "proving",
      abandoned_reason: r.abandoned_reason ?? undefined,
      pipeline: r.pipeline ?? null,
      prover: r.prover ?? null,
      opened_unix_millis: r.opened_unix_millis ?? null,
      closed_unix_millis: r.closed_unix_millis ?? null,
      justified: jparse(r.justified),
      finalized: jparse(r.finalized),
      latency: jparse(r.latency),
      stage_count: num(r.stage_count) ?? this.stageCount(r.epoch),
      prove_millis_total: num(r.prove_millis_total) ?? this.proveTotal(r.epoch),
      proof: this.proofObject(r),
    };
  }

  private serveEpochs(url: URL): Response {
    const q = url.searchParams;
    let limit = Number(q.get("limit") ?? "50");
    if (!Number.isFinite(limit) || limit <= 0) limit = 50;
    limit = Math.min(Math.floor(limit), 200);
    const where: string[] = [];
    const binds: any[] = [];
    const before = Number(q.get("before"));
    if (q.get("before") !== null && Number.isFinite(before)) {
      where.push("epoch < ?");
      binds.push(before);
    }
    const status = q.get("status");
    if (status) {
      where.push("status = ?");
      binds.push(status);
    }
    const clause = where.length ? ` WHERE ${where.join(" AND ")}` : "";
    const rows = this.all(`SELECT * FROM epochs${clause} ORDER BY epoch DESC LIMIT ?`, ...binds, limit);
    let nextBefore: number | null = null;
    if (rows.length === limit) {
      const lowest = rows[rows.length - 1].epoch as number;
      const more = this.all(
        `SELECT epoch FROM epochs${clause ? clause + " AND" : " WHERE"} epoch < ? ORDER BY epoch DESC LIMIT 1`,
        ...binds,
        lowest,
      );
      if (more.length) nextBefore = lowest;
    }
    return jsonResponse(
      {
        chain: this.chain(),
        count: rows.length,
        next_before: nextBefore,
        epochs: rows.map((r) => this.epochEntry(r)),
      },
      { headers: { "cache-control": "public, max-age=5" } },
    );
  }

  private stageObject(s: Row): any {
    const extra = jparse(s.extra) ?? {};
    return {
      ...extra,
      stage: s.stage,
      epoch: s.epoch,
      slot: s.slot ?? null,
      index: (s.idx as number) < 0 ? null : s.idx,
      started_unix_millis: s.started_unix_millis ?? null,
      finished_unix_millis: s.finished_unix_millis ?? null,
      millis: s.millis ?? null,
      prove_millis: s.prove_millis ?? null,
      wrap_millis: s.wrap_millis ?? null,
      witness: jparse(s.witness),
      proof_bytes: s.proof_bytes ?? null,
    };
  }

  // verify is assembled from stored rows when the daemon did not post one whole.
  private verifyObject(r: Row, proof: any, publicInputs: any): any {
    const stored = jparse(r.verify);
    if (stored) return stored;
    if (!proof) return null;
    const d = this.daemonRecord();
    return {
      stage: proof.stage ?? null,
      program: proof.program ?? null,
      program_vk: proof.program_vk ?? null,
      elf_sha256: proof.elf_sha256 ?? null,
      zisk_version: d.zisk_version ?? null,
      zkasper_commit: d.commit ?? null,
      chain: r.chain ?? this.chain(),
      public_bytes: proof.public_bytes ?? null,
      public_inputs: publicInputs,
      proof_url: `/v1/proofs/${r.epoch}`,
    };
  }

  private serveEpoch(epoch: number): Response {
    if (!Number.isFinite(epoch)) return err(400, "bad_request", "epoch must be a number");
    const r = this.one("SELECT * FROM epochs WHERE epoch = ?", epoch);
    if (!r) return err(404, "not_found", `epoch ${epoch} was never opened by this daemon`);
    const stages = this.all(
      "SELECT * FROM stages WHERE epoch = ?" +
        " ORDER BY COALESCE(started_unix_millis, finished_unix_millis, 0) ASC, stage ASC, idx ASC",
      epoch,
    );
    const proof = this.proofObject(r);
    const publicInputs = jparse(r.public_inputs);
    const body = {
      ...this.epochEntry(r),
      chain: r.chain ?? this.chain(),
      finalizes_epoch: r.finalizes_epoch ?? null,
      accumulator: jparse(r.accumulator),
      stages: stages.map((s) => this.stageObject(s)),
      wall_millis_total:
        num(r.wall_millis_total) ??
        (num(r.opened_unix_millis) !== null && num(r.closed_unix_millis) !== null
          ? (r.closed_unix_millis as number) - (r.opened_unix_millis as number)
          : null),
      public_inputs: publicInputs,
      verify: this.verifyObject(r, proof, publicInputs),
    };
    const settled = r.status === "proven" || r.status === "abandoned";
    return jsonResponse(body, {
      headers: { "cache-control": settled ? "public, max-age=86400" : "public, max-age=5" },
    });
  }

  private serveCursor(): Response {
    const missing = this.all(
      "SELECT e.epoch AS epoch FROM epochs e" +
        " LEFT JOIN proofs p ON p.epoch = e.epoch AND p.evicted = 0" +
        " WHERE e.proof IS NOT NULL AND json_extract(e.proof, '$.available') = 1 AND p.epoch IS NULL" +
        " ORDER BY e.epoch DESC LIMIT 200",
    );
    return jsonResponse({
      last_seq: this.getKvNum("last_daemon_seq") ?? 0,
      last_epoch: num(this.one("SELECT MAX(epoch) AS m FROM epochs")?.m),
      missing_proofs: missing.map((m) => m.epoch as number).reverse(),
    });
  }

  private reset(): Response {
    this.sql.exec(
      "DROP TABLE IF EXISTS events;" +
        "DROP TABLE IF EXISTS epochs;" +
        "DROP TABLE IF EXISTS stages;" +
        "DROP TABLE IF EXISTS proofs;" +
        "DROP TABLE IF EXISTS proof_chunks;" +
        "DROP TABLE IF EXISTS kv;",
    );
    this.migrate();
    // Stream seq stays monotonic across a reset so a connected client's
    // Last-Event-ID never points into the future.
    this.setKv("stream_seq", String(this.nextSeq - 1));
    return jsonResponse({ ok: true, reset: true, stream_seq: this.nextSeq - 1 });
  }

  // ---------------------------------------------------------------- proofs

  private async putProofMeta(request: Request, epoch: number): Promise<Response> {
    const m = await request.json<any>();
    this.sql.exec(
      "INSERT INTO proofs (epoch, backend, bytes, sha256, stage, program_vk, public_bytes, chunks, stored_millis, evicted)" +
        " VALUES (?, 'r2', ?, ?, ?, ?, ?, 0, ?, 0)" +
        " ON CONFLICT (epoch) DO UPDATE SET backend = 'r2', bytes = excluded.bytes, sha256 = excluded.sha256," +
        " stage = excluded.stage, program_vk = excluded.program_vk, public_bytes = excluded.public_bytes," +
        " chunks = 0, stored_millis = excluded.stored_millis, evicted = 0",
      epoch,
      m.bytes,
      m.sha256,
      m.stage ?? null,
      m.program_vk ?? null,
      m.public_bytes ?? null,
      Date.now(),
    );
    this.sql.exec("DELETE FROM proof_chunks WHERE epoch = ?", epoch);
    return jsonResponse({ ok: true, stored: "r2" });
  }

  private async putProofInline(request: Request, epoch: number): Promise<Response> {
    const buf = new Uint8Array(await request.arrayBuffer());
    const h = request.headers;
    this.sql.exec("DELETE FROM proof_chunks WHERE epoch = ?", epoch);
    let n = 0;
    for (let off = 0; off < buf.length; off += CHUNK_BYTES) {
      const slice = buf.slice(off, Math.min(off + CHUNK_BYTES, buf.length));
      this.sql.exec("INSERT INTO proof_chunks (epoch, n, data) VALUES (?, ?, ?)", epoch, n, slice.buffer);
      n++;
    }
    this.sql.exec(
      "INSERT INTO proofs (epoch, backend, bytes, sha256, stage, program_vk, public_bytes, chunks, stored_millis, evicted)" +
        " VALUES (?, 'inline', ?, ?, ?, ?, ?, ?, ?, 0)" +
        " ON CONFLICT (epoch) DO UPDATE SET backend = 'inline', bytes = excluded.bytes, sha256 = excluded.sha256," +
        " stage = excluded.stage, program_vk = excluded.program_vk, public_bytes = excluded.public_bytes," +
        " chunks = excluded.chunks, stored_millis = excluded.stored_millis, evicted = 0",
      epoch,
      buf.length,
      h.get("x-zkasper-sha256"),
      h.get("x-zkasper-stage"),
      h.get("x-zkasper-program-vk"),
      h.get("x-zkasper-public-bytes"),
      n,
      Date.now(),
    );
    const evicted = this.evict();
    return jsonResponse({ ok: true, stored: "inline", chunks: n, evicted });
  }

  // Oldest-first eviction. The row survives with evicted = 1 so the read path
  // can answer 410 instead of pretending the epoch never had a proof.
  private evict(): number[] {
    const gone: number[] = [];
    for (;;) {
      const total = num(this.one("SELECT COALESCE(SUM(bytes), 0) AS b FROM proofs WHERE backend = 'inline' AND evicted = 0")?.b) ?? 0;
      if (total <= INLINE_TOTAL_CAP) break;
      const oldest = this.one("SELECT epoch FROM proofs WHERE backend = 'inline' AND evicted = 0 ORDER BY epoch ASC LIMIT 1");
      if (!oldest) break;
      const e = oldest.epoch as number;
      this.sql.exec("DELETE FROM proof_chunks WHERE epoch = ?", e);
      this.sql.exec("UPDATE proofs SET evicted = 1, chunks = 0 WHERE epoch = ?", e);
      gone.push(e);
    }
    return gone;
  }

  private serveProofMeta(epoch: number): Response {
    if (!Number.isFinite(epoch)) return err(400, "bad_request", "epoch must be a number");
    const r = this.one("SELECT * FROM proofs WHERE epoch = ?", epoch);
    if (!r) {
      const e = this.one("SELECT proof FROM epochs WHERE epoch = ?", epoch);
      const p = e ? jparse(e.proof) : null;
      return jsonResponse({ found: false, known_epoch: !!e, declared: p });
    }
    return jsonResponse({
      found: true,
      backend: r.backend,
      bytes: r.bytes,
      sha256: r.sha256,
      stage: r.stage,
      program_vk: r.program_vk,
      public_bytes: r.public_bytes,
      evicted: r.evicted === 1,
    });
  }

  private serveProofBody(epoch: number): Response {
    const meta = this.one("SELECT bytes, chunks, evicted FROM proofs WHERE epoch = ? AND backend = 'inline'", epoch);
    if (!meta || meta.evicted === 1) return err(404, "not_found", "no inline proof bytes");
    const rows = this.all("SELECT data FROM proof_chunks WHERE epoch = ? ORDER BY n ASC", epoch);
    const out = new Uint8Array(meta.bytes as number);
    let off = 0;
    for (const row of rows) {
      const part = new Uint8Array(row.data as ArrayBuffer);
      out.set(part, off);
      off += part.length;
    }
    return new Response(out, { headers: { "content-type": "application/octet-stream" } });
  }

  // ---------------------------------------------------------------- SSE

  private frame(seq: number, type: string, data: any): Uint8Array {
    return enc.encode(`id: ${seq}\nevent: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  private push(sub: Sub, bytes: Uint8Array): void {
    if (sub.dead) return;
    sub.chain = sub.chain.then(
      () => sub.writer.write(bytes),
      () => {},
    ).catch(() => {
      sub.dead = true;
      this.subs.delete(sub);
      this.stopKeepaliveIfIdle();
      try {
        sub.writer.close();
      } catch {}
    });
  }

  private broadcast(seq: number, type: string, data: any): void {
    if (this.subs.size === 0) return;
    const bytes = this.frame(seq, type, data);
    for (const sub of this.subs) this.push(sub, bytes);
  }

  private startKeepalive(): void {
    if (this.keepalive !== null) return;
    const beat = enc.encode(": keepalive\n\n");
    this.keepalive = setInterval(() => {
      for (const sub of this.subs) this.push(sub, beat);
    }, KEEPALIVE_MS);
  }

  private stopKeepaliveIfIdle(): void {
    if (this.subs.size === 0 && this.keepalive !== null) {
      clearInterval(this.keepalive);
      this.keepalive = null;
    }
  }

  private serveLive(request: Request, url: URL): Response {
    if (this.subs.size >= MAX_STREAMS) {
      return err(503, "too_many_streams", `at most ${MAX_STREAMS} live streams are held at once`);
    }
    const lastId = request.headers.get("last-event-id");
    const sinceParam = url.searchParams.get("since") ?? lastId;
    const since = sinceParam === null ? null : Number(sinceParam);
    const wantReplay = url.searchParams.get("replay") !== "0" && since !== null && Number.isFinite(since);

    // Everything below runs in one synchronous turn, so no event can slip
    // between the replay query and the subscription.
    const head = this.nextSeq - 1;
    // hello is anchored at the resume point, not the head: a client that drops
    // mid-replay and reconnects from the last id it saw must not skip the
    // replayed range.
    const anchor = wantReplay ? (since as number) : head;
    const parts: Uint8Array[] = [this.frame(anchor, "hello", { seq: anchor, unix_millis: Date.now(), status: this.buildStatus() })];
    if (wantReplay) {
      for (const row of this.all("SELECT seq, type, data FROM events WHERE seq > ? ORDER BY seq ASC LIMIT ?", since, RING_EVENTS)) {
        parts.push(this.frame(row.seq as number, row.type as string, jparse(row.data)));
      }
    }

    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const sub: Sub = { writer: writable.getWriter(), chain: Promise.resolve(), dead: false };
    this.subs.add(sub);
    this.startKeepalive();
    for (const p of parts) this.push(sub, p);

    const drop = () => {
      if (sub.dead) return;
      sub.dead = true;
      this.subs.delete(sub);
      this.stopKeepaliveIfIdle();
      sub.writer.close().catch(() => {});
    };
    try {
      request.signal.addEventListener("abort", drop);
    } catch {}

    return new Response(readable, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
      },
    });
  }
}
