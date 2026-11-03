// Worker thread for the embedded proving replica. PGlite runs on one
// thread and ignores statement_timeout, so the parent enforces a wall-clock
// limit by terminating this thread. Plain JS on purpose: it loads with no
// bundler aliases. It only ever runs SQL the parent sends for its own replica.
import { parentPort } from "node:worker_threads";
import { PGlite } from "@electric-sql/pglite";

const db = await PGlite.create();
// PGlite keeps temp files in memory outside any heap limit; a policy that
// spills (a huge sort or array_agg) grew the process past 7 GB. These bound it
// to a Postgres error. Changing them needs superuser, which probes never have.
await db.exec("set temp_file_limit = '64MB'; set work_mem = '16MB'; set maintenance_work_mem = '32MB';");
parentPort.on("message", async ({ id, sql }) => {
  try {
    const results = await db.exec(sql);
    const withRows = results.filter((r) => r.fields.length > 0);
    // Probes read counts; a bounded prefix is all any caller needs, and an
    // unbounded result must not be copied into the parent's heap.
    parentPort.postMessage({ id, rows: (withRows[withRows.length - 1]?.rows ?? []).slice(0, 200) });
  } catch (err) {
    // A probe that fails inside begin...commit leaves the session in an aborted
    // transaction, and every later statement, teardown included, would fail.
    await db.exec("rollback").catch(() => {});
    parentPort.postMessage({ id, error: err instanceof Error ? err.message.slice(0, 500) : "query failed" });
  }
});
parentPort.postMessage({ ready: true });
