import { NextResponse } from "next/server";

/** Provisional per-account caps enforced in the database (migrations
 * 082-083). The numbers await Felipe's measured approval; the refusals are
 * shown to the customer plainly and never as a generic failure. */
const CODES = {
  "audit quota reached": "audit_quota_reached",
  "recheck quota reached": "recheck_quota_reached",
  "repair quota reached": "repair_quota_reached",
  "token limit reached": "token_limit_reached",
} as const;
type QuotaCode = (typeof CODES)[keyof typeof CODES];

const MESSAGES: Record<QuotaCode, string> = {
  audit_quota_reached: "You have run 20 audits in the last 24 hours, the current limit. Scheduled and pull request checks keep running; try a manual audit again later.",
  recheck_quota_reached: "You have asked for 20 rechecks in the last 24 hours, the current limit. Scheduled monitoring keeps running; try again later.",
  repair_quota_reached: "You have requested 30 fixes in the last 24 hours, the current limit. Try again later.",
  token_limit_reached: "You have 10 active tokens, the current limit. Revoke one you no longer use, then create a new one.",
};

/** Maps a database error message to its quota code, or null. */
export function quotaCode(message: string): QuotaCode | null {
  for (const [text, code] of Object.entries(CODES)) if (message.includes(text)) return code;
  return null;
}

/** A 429 response with a plain message for a database quota error; null for any
 * other error. */
export function quotaResponse(error: unknown): NextResponse | null {
  if (!(error instanceof Error) || !(error.message in MESSAGES)) return null;
  return NextResponse.json({ error: MESSAGES[error.message as QuotaCode] }, { status: 429 });
}
