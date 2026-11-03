import { join } from "node:path";
import { Worker } from "node:worker_threads";
import type { ProvingHost } from "./arena";

// The disposable replica host, embedded. Felipe (2026-09-23): no paid
// Supabase project for ShipLock's own proving infrastructure. Each proof gets
// a fresh in-process Postgres (PGlite, WASM) in its own worker thread, holding
// only synthetic tenants, thrown away afterwards. It has no network and no
// file system, so the customer's policy text, which the replica executes,
// cannot reach anything. A statement that runs past its limit terminates the
// thread: PGlite ignores statement_timeout, so this is the only real limit.
//
// The prelude recreates the Supabase pieces a policy relies on: the anon and
// authenticated roles and auth.uid()/auth.role()/auth.jwt() reading
// request.jwt.claims, which is how the probes sign in as a synthetic tenant.
const PRELUDE = `
  create role anon nologin;
  create role authenticated nologin;
  create schema auth;
  create function auth.uid() returns uuid language sql stable as
    $$ select nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid $$;
  create function auth.role() returns text language sql stable as
    $$ select nullif(current_setting('request.jwt.claims', true)::json->>'role', '') $$;
  create function auth.jwt() returns jsonb language sql stable as
    $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
  grant usage on schema auth to anon, authenticated;
  grant execute on all functions in schema auth to anon, authenticated;
`;

/** Project-relative, so next.config.ts can trace exactly this file. */
export const EMBEDDED_WORKER_PATH = "lib/proving/embeddedWorker.mjs";

interface EmbeddedHost extends ProvingHost {
  close(): Promise<void>;
}

type Reply = { id?: number; rows?: Record<string, unknown>[]; error?: string; ready?: boolean };

/** Opens an in-process Postgres (PGlite) replica in a worker thread, with a
 * per-statement time limit, bounded memory and no network or file access. */
export async function openEmbeddedHost({ statementTimeoutMs = 5_000 }: { statementTimeoutMs?: number } = {}): Promise<EmbeddedHost> {
  // A heap limit so a runaway JS-side allocation ends only this thread
  // (ERR_WORKER_OUT_OF_MEMORY), not the server process. It does not bound
  // PGlite's WASM memory (capped at 2 GB by PGlite) or its in-memory temp
  // files; the worker bounds those with temp_file_limit (embeddedWorker.mjs).
  // Resolved from the project root at run time, never bundled: Turbopack
  // cannot resolve a worker script as a module. The file and PGlite reach the
  // job routes' functions through outputFileTracingIncludes (next.config.ts).
  const worker = new Worker(/* turbopackIgnore: true */ join(process.cwd(), EMBEDDED_WORKER_PATH), {
    resourceLimits: { maxOldGenerationSizeMb: 256, maxYoungGenerationSizeMb: 32, stackSizeMb: 4 },
  });
  const pending = new Map<number, { resolve: (rows: Record<string, unknown>[]) => void; reject: (err: Error) => void }>();
  let dead: Error | null = null;
  let next = 0;
  const kill = async (reason: Error) => {
    dead = reason;
    for (const waiter of pending.values()) waiter.reject(reason);
    pending.clear();
    await worker.terminate();
  };
  worker.on("error", (err) => { void kill(err instanceof Error ? err : new Error("embedded host failed")); });
  worker.on("message", (reply: Reply) => {
    if (reply.id === undefined) return;
    const waiter = pending.get(reply.id);
    if (!waiter) return;
    pending.delete(reply.id);
    if (reply.error !== undefined) waiter.reject(new Error(reply.error));
    else waiter.resolve(reply.rows ?? []);
  });
  await new Promise<void>((resolve, reject) => {
    const onReady = (reply: Reply) => { if (reply.ready) { worker.off("message", onReady); resolve(); } };
    worker.on("message", onReady);
    worker.once("error", reject);
  });

  // The limit bounds customer SQL. The host's own setup gets a fixed, larger
  // bound: under the customer limit a slow machine killed the replica before
  // its first statement (CI, 2026-11-02).
  const exec = (sql: string, limitMs = statementTimeoutMs) => new Promise<Record<string, unknown>[]>((resolve, reject) => {
    if (dead) return reject(dead);
    const id = next++;
    const timer = setTimeout(() => {
      void kill(new Error(`Embedded replica statement exceeded ${limitMs} ms and was stopped.`));
    }, limitMs);
    pending.set(id, {
      resolve: (rows) => { clearTimeout(timer); resolve(rows); },
      reject: (err) => { clearTimeout(timer); reject(err); },
    });
    worker.postMessage({ id, sql });
  });

  await exec(PRELUDE, Math.max(statementTimeoutMs, 30_000));
  const projectRef = `embedded-${crypto.randomUUID()}`;
  return {
    token: "",
    projectRef,
    async run(ref, sql) {
      // Same contract as the hosted path: statements go only to this replica.
      if (ref !== projectRef) throw new Error("The embedded proving host runs only its own replica.");
      return exec(sql);
    },
    close: async () => { if (!dead) await kill(new Error("Embedded replica closed.")); },
  };
}
