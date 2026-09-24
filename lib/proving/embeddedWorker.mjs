// Worker thread for the embedded proving replica (6A-2a). PGlite runs on one
// thread and ignores statement_timeout, so the parent enforces a wall-clock
// limit by terminating this thread. Plain JS on purpose: it loads with no
// bundler aliases. It only ever runs SQL the parent sends for its own replica.
import { parentPort } from "node:worker_threads";
import { PGlite } from "@electric-sql/pglite";

const db = await PGlite.create();
parentPort.on("message", async ({ id, sql }) => {
  try {
    const results = await db.exec(sql);
    const withRows = results.filter((r) => r.fields.length > 0);
    parentPort.postMessage({ id, rows: withRows[withRows.length - 1]?.rows ?? [] });
  } catch (err) {
    parentPort.postMessage({ id, error: err instanceof Error ? err.message.slice(0, 500) : "query failed" });
  }
});
parentPort.postMessage({ ready: true });
