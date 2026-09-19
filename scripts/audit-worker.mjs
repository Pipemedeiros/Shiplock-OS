const baseUrl = process.env.SHIPLOCK_BASE_URL;
const secret = process.env.CRON_SECRET;
const pollMs = Number(process.env.SHIPLOCK_WORKER_POLL_MS ?? 2_000);

if (!baseUrl || !secret) {
  console.error("SHIPLOCK_BASE_URL and CRON_SECRET are required.");
  process.exit(1);
}

const endpoint = new URL("/api/jobs/drain", baseUrl);
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

let stopping = false;
process.on("SIGINT", () => { stopping = true; });
process.on("SIGTERM", () => { stopping = true; });

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

while (!stopping) {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${secret}` },
      signal: AbortSignal.timeout(65_000),
    });
    if (response.status === 401) throw new Error("Worker authorization was refused.");
    if (!response.ok) throw new Error(`Worker wake failed with HTTP ${response.status}.`);
    const body = await response.json();
    if (body?.processed === 1) continue;
    await wait(pollMs);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Worker wake failed.");
    await wait(Math.max(pollMs, 5_000));
  }
}
