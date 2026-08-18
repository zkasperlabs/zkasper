// zkasper public API. Router + auth + proof-byte storage; all state lives in the
// single IndexDO (see index-do.ts).
//
// Ops:
//   npx --yes wrangler@4 deploy                       (from api/)
//   npx --yes wrangler@4 secret put INGEST_TOKEN      (value on stdin)
// Proof bytes go to R2 when a PROOFS bucket binding exists and to the DO's own
// SQLite otherwise; adding the binding to wrangler.jsonc and redeploying is the
// only change needed to switch.
export { IndexDO } from "./index-do";

const MAX_INGEST_JSON = 1024 * 1024;
const MAX_PROOF_INLINE = 8 * 1024 * 1024;
const MAX_PROOF_R2 = 64 * 1024 * 1024;

const CORS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, HEAD, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, last-event-id",
  "access-control-expose-headers":
    "etag, content-length, x-zkasper-epoch, x-zkasper-stage, x-zkasper-program-vk, x-zkasper-public-bytes, x-zkasper-sha256",
  "access-control-max-age": "86400",
  vary: "origin",
};

interface Env {
  INDEX: DurableObjectNamespace;
  PROOFS?: R2Bucket;
  INGEST_TOKEN?: string;
}

function withCors(res: Response): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(CORS)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extra },
  });
}

function fail(status: number, error: string, message: string): Response {
  return json({ error, message }, status);
}

function hex(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return "0x" + hex(await crypto.subtle.digest("SHA-256", bytes));
}

// Constant time: compare digests, so neither the value nor its length leaks.
async function tokenOk(header: string | null, secret: string | undefined): Promise<boolean> {
  if (!secret) return false;
  const m = /^Bearer\s+(.+)$/i.exec(header ?? "");
  if (!m) return false;
  const e = new TextEncoder();
  const a = await crypto.subtle.digest("SHA-256", e.encode(m[1]));
  const b = await crypto.subtle.digest("SHA-256", e.encode(secret));
  return crypto.subtle.timingSafeEqual(a, b);
}

function stub(env: Env): DurableObjectStub {
  return env.INDEX.get(env.INDEX.idFromName("v1"));
}

function doUrl(path: string, search = ""): string {
  return `https://index.zkasper.internal${path}${search}`;
}

const proofKey = (epoch: number) => `proofs/${epoch}.bin`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return withCors(await route(request, env));
    } catch (e: any) {
      return withCors(fail(500, "internal", String(e && e.message ? e.message : e)));
    }
  },
};

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") return new Response(null, { status: 204 });

  if (path === "/v1/health" || path === "/health") {
    if (method !== "GET" && method !== "HEAD") return fail(405, "method_not_allowed", "GET only");
    return json({ ok: true });
  }

  if (path === "/v1/ingest" && method === "POST") return ingest(request, env);
  if (path === "/v1/ingest/reset" && method === "POST") return reset(request, env);
  if (path === "/v1/ingest/cursor") {
    if (method !== "GET") return fail(405, "method_not_allowed", "GET only");
    if (!(await tokenOk(request.headers.get("authorization"), env.INGEST_TOKEN))) {
      return fail(401, "unauthorized", "bearer token required");
    }
    return stub(env).fetch(doUrl("/do/cursor"));
  }
  const ingestProof = /^\/v1\/ingest\/proof\/(\d+)$/.exec(path);
  if (ingestProof && method === "POST") return putProof(request, env, Number(ingestProof[1]));

  if (path === "/v1/status") {
    if (method !== "GET" && method !== "HEAD") return fail(405, "method_not_allowed", "GET only");
    return stub(env).fetch(doUrl("/do/status"));
  }

  if (path === "/v1/epochs") {
    if (method !== "GET" && method !== "HEAD") return fail(405, "method_not_allowed", "GET only");
    return stub(env).fetch(doUrl("/do/epochs", url.search));
  }

  const one = /^\/v1\/epochs\/(\d+)$/.exec(path);
  if (one) {
    if (method !== "GET" && method !== "HEAD") return fail(405, "method_not_allowed", "GET only");
    return stub(env).fetch(doUrl(`/do/epoch/${one[1]}`));
  }

  const pr = /^\/v1\/proofs\/(\d+)$/.exec(path);
  if (pr) {
    if (method !== "GET" && method !== "HEAD") return fail(405, "method_not_allowed", "GET or HEAD only");
    return getProof(env, Number(pr[1]), method === "HEAD");
  }

  if (path === "/v1/live") {
    if (method !== "GET") return fail(405, "method_not_allowed", "GET only");
    const headers = new Headers();
    const lastId = request.headers.get("last-event-id");
    if (lastId) headers.set("last-event-id", lastId);
    return stub(env).fetch(doUrl("/do/live", url.search), { headers });
  }

  return fail(404, "not_found", `no route for ${method} ${url.pathname}`);
}

async function ingest(request: Request, env: Env): Promise<Response> {
  if (!(await tokenOk(request.headers.get("authorization"), env.INGEST_TOKEN))) {
    return fail(401, "unauthorized", "bearer token required");
  }
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_INGEST_JSON) {
    return fail(413, "too_large", `ingest body must be at most ${MAX_INGEST_JSON} bytes`);
  }
  const text = await request.text();
  if (text.length > MAX_INGEST_JSON) {
    return fail(413, "too_large", `ingest body must be at most ${MAX_INGEST_JSON} bytes`);
  }
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    return fail(400, "bad_request", "body is not valid JSON");
  }
  if (!body || typeof body !== "object") return fail(400, "bad_request", "body must be a JSON object");
  return stub(env).fetch(doUrl("/do/ingest"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function reset(request: Request, env: Env): Promise<Response> {
  if (!(await tokenOk(request.headers.get("authorization"), env.INGEST_TOKEN))) {
    return fail(401, "unauthorized", "bearer token required");
  }
  if (env.PROOFS) {
    const listed = await env.PROOFS.list({ prefix: "proofs/" });
    await Promise.all(listed.objects.map((o: any) => env.PROOFS!.delete(o.key)));
  }
  return stub(env).fetch(doUrl("/do/reset"), { method: "POST" });
}

async function putProof(request: Request, env: Env, epoch: number): Promise<Response> {
  if (!(await tokenOk(request.headers.get("authorization"), env.INGEST_TOKEN))) {
    return fail(401, "unauthorized", "bearer token required");
  }
  const cap = env.PROOFS ? MAX_PROOF_R2 : MAX_PROOF_INLINE;
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > cap) {
    return fail(413, "too_large", `proof must be at most ${cap} bytes`);
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > cap) return fail(413, "too_large", `proof must be at most ${cap} bytes`);
  if (bytes.length === 0) return fail(400, "bad_request", "empty proof body");
  if (bytes.length % 8 !== 0) return fail(400, "bad_request", "proof length must be a multiple of 8");

  const sha = await sha256Hex(bytes);
  const claimed = (request.headers.get("x-zkasper-sha256") ?? "").toLowerCase();
  if (claimed && claimed !== sha) {
    return fail(400, "sha256_mismatch", `body hashes to ${sha}, header claims ${claimed}`);
  }
  const meta = {
    bytes: bytes.length,
    sha256: sha,
    stage: request.headers.get("x-zkasper-stage"),
    program_vk: request.headers.get("x-zkasper-program-vk"),
    public_bytes: request.headers.get("x-zkasper-public-bytes"),
  };

  if (env.PROOFS) {
    await env.PROOFS.put(proofKey(epoch), bytes, {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: {
        sha256: sha,
        stage: meta.stage ?? "",
        program_vk: meta.program_vk ?? "",
      },
    });
    const r = await stub(env).fetch(doUrl(`/do/proof-meta-put/${epoch}`), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(meta),
    });
    if (!r.ok) return r;
    return json({ ok: true, bytes: bytes.length, sha256: sha, stored: "r2" });
  }

  const headers = new Headers({ "content-type": "application/octet-stream", "x-zkasper-sha256": sha });
  if (meta.stage) headers.set("x-zkasper-stage", meta.stage);
  if (meta.program_vk) headers.set("x-zkasper-program-vk", meta.program_vk);
  if (meta.public_bytes) headers.set("x-zkasper-public-bytes", meta.public_bytes);
  const r = await stub(env).fetch(doUrl(`/do/proof-inline/${epoch}`), { method: "POST", headers, body: bytes });
  if (!r.ok) return r;
  const info = await r.json<any>();
  return json({ ok: true, bytes: bytes.length, sha256: sha, stored: "inline", evicted: info.evicted ?? [] });
}

async function getProof(env: Env, epoch: number, headOnly: boolean): Promise<Response> {
  const metaRes = await stub(env).fetch(doUrl(`/do/proof-meta/${epoch}`));
  const meta = await metaRes.json<any>();
  if (!meta.found) {
    return fail(404, "not_found", `epoch ${epoch} has no stored proof bytes`);
  }
  if (meta.evicted) {
    return fail(410, "gone", `proof bytes for epoch ${epoch} were evicted from the inline store`);
  }

  const headers = new Headers({
    "content-type": "application/octet-stream",
    "content-length": String(meta.bytes),
    etag: `"${meta.sha256}"`,
    "cache-control": "public, max-age=31536000, immutable",
    "x-zkasper-epoch": String(epoch),
    "x-zkasper-sha256": meta.sha256,
  });
  if (meta.stage) headers.set("x-zkasper-stage", meta.stage);
  if (meta.program_vk) headers.set("x-zkasper-program-vk", meta.program_vk);
  if (meta.public_bytes) headers.set("x-zkasper-public-bytes", meta.public_bytes);
  if (headOnly) return new Response(null, { status: 200, headers });

  if (meta.backend === "r2") {
    if (!env.PROOFS) return fail(503, "unavailable", "proof bytes live in R2 but no bucket is bound");
    const obj = await env.PROOFS.get(proofKey(epoch));
    if (!obj) return fail(404, "not_found", `epoch ${epoch} has no stored proof bytes`);
    return new Response(obj.body, { status: 200, headers });
  }
  const body = await stub(env).fetch(doUrl(`/do/proof-body/${epoch}`));
  if (!body.ok) return fail(404, "not_found", `epoch ${epoch} has no stored proof bytes`);
  return new Response(body.body, { status: 200, headers });
}
