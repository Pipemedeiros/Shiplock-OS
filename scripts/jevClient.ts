import type { JevRequest, JevResponse } from "../lib/judge/jev";

// DEVELOPER TOOL ONLY. ShipLock the product makes no model call (Felipe,
// 2026-10-01). This is the harness's call to TypeSafe's JEV
// (docs.typesafe.ai/api), run on Felipe's own key (TYPESAFE_API_KEY, read
// from his environment, never logged) with --confirm-paid and a dollar cap,
// to measure whether a calibrated judge predicts the blind labels. The
// request is the product's own (lib/judge/jev.ts).
export const JEV_ENDPOINT = "https://api.typesafe.ai/v1/systemone";
/** Published price: $0.042 per million input tokens; output is not billed. */
export const JEV_USD_PER_INPUT_TOKEN = 0.042 / 1e6;

export async function systemOne(request: JevRequest, apiKey: string, timeoutMs = 60_000): Promise<JevResponse> {
  const res = await fetch(JEV_ENDPOINT, {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`JEV HTTP ${res.status}`);
  return (await res.json()) as JevResponse;
}
