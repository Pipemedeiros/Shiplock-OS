import { createHash } from "crypto";
import type { NextRequest } from "next/server";

// x-forwarded-for is a comma-separated hop chain: "client-claimed, ..., nearest-proxy".
// Each hop APPENDS its own observed peer IP rather than replacing what came before,
// so the first entry is whatever the caller claims (fully attacker-controlled) and
// the last entry is what our nearest trusted proxy (e.g. Vercel's edge) actually saw.
// x-real-ip, when present, is set directly by the proxy and isn't a hop chain at all.
// NOTE: this only holds when there genuinely is a trusted proxy in front of the app
// (e.g. deployed on Vercel). In local dev there is no proxy, so this header is fully
// attacker-controlled either way — confirmed during the 2026-06-22 security audit.
export function getClientIpHash(req: NextRequest): string {
  const realIp = req.headers.get("x-real-ip");
  const forwardedChain = req.headers.get("x-forwarded-for");
  const lastHop = forwardedChain?.split(",").pop()?.trim();
  const ip = realIp || lastHop || "anonymous";
  return createHash("sha256").update(ip).digest("hex");
}
