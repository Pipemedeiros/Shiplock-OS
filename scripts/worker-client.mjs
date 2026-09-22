export function workerEndpoints(baseUrl) {
  return {
    drain: new URL("/api/jobs/drain", baseUrl),
    schedule: new URL("/api/jobs/schedule", baseUrl),
  };
}

async function post(endpoint, secret, fetchImpl) {
  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}` },
    signal: AbortSignal.timeout(65_000),
  });
  if (response.status === 401) throw new Error("Worker authorization was refused.");
  if (!response.ok) throw new Error(`Worker request failed with HTTP ${response.status}.`);
  return response.json();
}

/** One bounded scheduler admission followed by one bounded execution claim. */
export async function runWorkerCycle({ baseUrl, secret, schedule, fetchImpl = fetch }) {
  const endpoints = workerEndpoints(baseUrl);
  let scheduleMore = false;
  if (schedule) {
    const admitted = await post(endpoints.schedule, secret, fetchImpl);
    scheduleMore = admitted?.more === true;
  }
  const drained = await post(endpoints.drain, secret, fetchImpl);
  return { processed: drained?.processed === 1, scheduleMore };
}
