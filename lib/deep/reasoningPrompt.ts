import type { ReasoningContext } from "./reasoningContext";

// System prompt for the reasoning pass. Methodology distilled from the standard
// pentest playbooks (Supabase RLS/RPC, broken access control, IDOR, mass
// assignment, injection sinks). It reasons over a PRE-BUILT map — it does not
// explore — and it is FORBIDDEN from claiming proof: every finding is an
// explicit hypothesis with a confidence and a code location to verify. This is
// what keeps ShipLock honest (reasoned ≠ exploit-proven) and the call cheap.
export const REASONING_SYSTEM_PROMPT = `You are a senior application security reviewer analysing a MAP of a Supabase-backed app's attack surface (endpoints, their auth checks, and Postgres functions). You did NOT run the app and CANNOT prove anything — you reason about likely risk from the map only.

Judge these patterns:
1. Broken access control (A01): a mutating endpoint (mutates:true) with hasOwnershipScope:false is a likely IDOR / missing-ownership-check — anyone authenticated may act on another user's records.
2. Privilege escalation: an RPC with securityDefiner:true AND anonExecute:true runs as its owner and bypasses RLS — callable without auth is a critical risk.
3. Mass assignment / business-logic tampering: usesClientInputInWrite:true means client-supplied fields flow into a write — check for price/role/quantity/user_id tampering.
4. Missing auth: mutating endpoint with hasAuth:false.

RULES:
- NEVER claim proof or that you exploited anything. Each finding is a hypothesis.
- Every finding needs a confidence ("high" | "medium" | "low") and a location (the file path from the map).
- Prefer fewer, higher-signal findings. Do not invent issues not supported by the map.
- Plain English, no jargon. severity is "CRITICAL" | "WARNING" | "INFO".
- Return ONLY valid JSON:
{
  "findings": [
    { "title": string, "severity": "CRITICAL"|"WARNING"|"INFO", "consequence": string, "location": string, "confidence": "high"|"medium"|"low", "why": string }
  ]
}`;

export function buildReasoningUserPrompt(ctx: ReasoningContext): string {
  const endpoints = ctx.endpoints.map((e) => ({
    path: e.path,
    methods: e.methods,
    mutates: e.mutates,
    hasAuth: e.hasAuth,
    hasOwnershipScope: e.hasOwnershipScope,
    usesClientInputInWrite: e.usesClientInputInWrite,
  }));
  const rpcs = ctx.rpcs.map((r) => ({
    name: r.name,
    file: r.file,
    securityDefiner: r.securityDefiner,
    anonExecute: r.anonExecute,
  }));
  return JSON.stringify({ endpoints, rpcs }, null, 2);
}
