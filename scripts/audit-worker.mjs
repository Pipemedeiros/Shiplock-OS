import { runWorkerCycle, workerEndpoints } from "./worker-client.mjs";

const baseUrl = process.env.SHIPLOCK_BASE_URL;
const secret = process.env.CRON_SECRET;
const pollMs = Number(process.env.SHIPLOCK_WORKER_POLL_MS ?? 2_000);
const scheduleMs = Number(process.env.SHIPLOCK_WORKER_SCHEDULE_MS ?? 60_000);

if (!baseUrl || !secret) {
  console.error("SHIPLOCK_BASE_URL and CRON_SECRET are required.");
  process.exit(1);
}

const endpoint = workerEndpoints(baseUrl).drain;
const localHttp = endpoint.protocol === "http:" &&
  ["localhost", "127.0.0.1", "::1"].includes(endpoint.hostname);
if (endpoint.protocol !== "https:" && !localHttp) {
  console.error("Worker secrets require HTTPS, except on localhost.");
  process.exit(1);
}
if (!Number.isInteger(pollMs) || pollMs < 250 || pollMs > 60_000) {
  console.error("SHIPLOCK_WORKER_POLL_MS must be an integer from 250 to 60000.");
  process.exit(1);
}
if (!Number.isInteger(scheduleMs) || scheduleMs < 1_000 || scheduleMs > 3_600_000) {
  console.error("SHIPLOCK_WORKER_SCHEDULE_MS must be an integer from 1000 to 3600000.");
  process.exit(1);
}

let stopping = false;
process.on("SIGINT", () => { stopping = true; });
process.on("SIGTERM", () => { stopping = true; });

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let nextScheduleAt = 0;
while (!stopping) {
  try {
    const now = Date.now();
    const cycle = await runWorkerCycle({
      baseUrl,
      secret,
      schedule: now >= nextScheduleAt,
    });
    if (now >= nextScheduleAt) nextScheduleAt = cycle.scheduleMore ? 0 : now + scheduleMs;
    if (cycle.processed || cycle.scheduleMore) continue;
    await wait(pollMs);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Worker wake failed.");
    await wait(Math.max(pollMs, 5_000));
  }
}
