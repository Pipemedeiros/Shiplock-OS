/**
 * Attack probes in a request line, classified where the request lands.
 *
 * Clean-room rules in the style of Cloudflare's managed WAF rules and the
 * OWASP Core Rule Set (CRS, Apache 2.0; patterns written here, not copied),
 * run inside the customer's own middleware as Aikido Zen runs inside the app.
 * The snippet reads the path and query in the customer's compute and sends
 * ShipLock only the category; a query value never leaves the customer's
 * server (traffic boundary, AGENTS.md). The same rules, as data, are embedded
 * in every snippet variant (lib/traffic/snippet.ts), so what is tested here
 * is what runs there.
 *
 * Order matters: the first match names the probe, so a command that also
 * reads a sensitive file is command injection, not traversal.
 *
 * Tuned to stay quiet on ordinary traffic: each rule needs the shape of an
 * attack (a quote then a boolean, two traversal steps, a metadata address),
 * not a single suspicious word.
 */
export const PROBE_KINDS = ["sqli", "traversal", "xss", "ssrf", "cmdi", "nosql"] as const;
export type ProbeKind = (typeof PROBE_KINDS)[number];

export const PROBE_RULES: { kind: ProbeKind; source: string; flags: string }[] = [
  { kind: "sqli", flags: "i", source: String.raw`'\s*(or|and)\s*('|\d)|\bunion\s+(all\s+)?select\b|;\s*(drop|delete|insert|update|truncate)\s+\w|\b(sleep|benchmark|pg_sleep)\s*\(\s*\d|\binformation_schema\b|'\s*--` },
  { kind: "cmdi", flags: "i", source: String.raw`(;|\||&&|\x60|\$\()\s*(cat|id|whoami|uname|curl|wget|nc|bash|sh|powershell)\b` },
  { kind: "traversal", flags: "i", source: String.raw`(\.\.[\/\\]){2,}|[\/\\](etc[\/\\](passwd|shadow|hosts)|win\.ini|boot\.ini)\b` },
  { kind: "xss", flags: "i", source: String.raw`<\s*script\b|javascript\s*:|<[^>]+\son(error|load|mouseover|focus)\s*=` },
  { kind: "ssrf", flags: "i", source: String.raw`=\s*(https?:)?\/\/(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\])` },
  { kind: "nosql", flags: "i", source: String.raw`\[\s*\$(ne|gt|gte|lt|regex|where|exists)\s*\]|\$where\b` },
];

const COMPILED = PROBE_RULES.map((r) => ({ kind: r.kind, re: new RegExp(r.source, r.flags) }));

/** Decodes up to twice (attackers double-encode), never throwing. */
function decode(text: string): string {
  let out = text.replace(/\+/g, " ");
  for (let i = 0; i < 2; i++) {
    try { const next = decodeURIComponent(out); if (next === out) break; out = next; } catch { break; }
  }
  return out;
}

/** The first probe kind a request line shows, or null. */
export function classifyProbe(pathAndQuery: string): ProbeKind | null {
  const text = decode(pathAndQuery.slice(0, 4096));
  for (const rule of COMPILED) if (rule.re.test(text)) return rule.kind;
  return null;
}

/** The classifier as source for a snippet: rules as data, the same loop. */
export function probeSnippetSource(): string {
  return `const SHIPLOCK_PROBES = ${JSON.stringify(PROBE_RULES)}.map((r) => ({ kind: r.kind, re: new RegExp(r.source, r.flags) }));
function probeKind(pathAndQuery) {
  let text = String(pathAndQuery).slice(0, 4096).replace(/\\+/g, " ");
  for (let i = 0; i < 2; i++) { try { const next = decodeURIComponent(text); if (next === text) break; text = next; } catch { break; } }
  for (const rule of SHIPLOCK_PROBES) if (rule.re.test(text)) return rule.kind;
  return null;
}`;
}
