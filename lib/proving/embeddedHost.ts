import { Worker } from "node:worker_threads";
import type { ProvingHost } from "./arena";

// The disposable replica host, embedded (6A-2a). Felipe (2026-09-23): no paid
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

export interface EmbeddedHost extends ProvingHost {
  close(): Promise<void>;
}

type Reply = { id?: number; rows?: Record<string, unknown>[]; error?: string; ready?: boolean };

export async function openEmbeddedHost({ statementTimeoutMs = 5_000 }: { statementTimeoutMs?: number } = {}): Promise<EmbeddedHost> {
  const worker = new Worker(new URL("./embeddedWorker.mjs", import.meta.url));
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

  const exec = (sql: string) => new Promise<Record<string, unknown>[]>((resolve, reject) => {
    if (dead) return reject(dead);
    const id = next++;
    const timer = setTimeout(() => {
      void kill(new Error(`Embedded replica statement exceeded ${statementTimeoutMs} ms and was stopped.`));
    }, statementTimeoutMs);
    pending.set(id, {
      resolve: (rows) => { clearTimeout(timer); resolve(rows); },
      reject: (err) => { clearTimeout(timer); reject(err); },
    });
    worker.postMessage({ id, sql });
  });

  await exec(PRELUDE);
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
