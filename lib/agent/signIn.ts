import type { RouteFact } from "@/lib/graph/routeInventory";
import type { StackReport } from "./stack";

/**
 * Whether the application has any notion of a signed-in person.
 *
 * Release attempt 5 found 5 of its 9 false findings in apps that sign no one
 * in by design: a single-tenant demo with a hard-coded identity and a
 * self-hosted single-user tool. "Anyone can edit any farm" is true there, but
 * there is no other account to reach, and whether the app is meant to be open
 * is the founder's decision, not something code can settle.
 *
 * "absent" is claimed only when every sign of an account is missing AND the
 * whole repository was read; a truncated read is "unknown". The signs are
 * deliberately broad: a wrong "present" keeps a finding as it was, a wrong
 * "absent" would move a real one to To review.
 */
type SignIn = "present" | "absent" | "unknown";

const USER_TABLE = /^(auth_)?(users?|usuarios?|utilisateurs?|benutzer|profiles?|accounts?|members?|sessions?)$/i;
const SIGN_IN_PATH = /(^|[/(_.-])(login|log-in|signin|sign-in|signup|sign-up|register|logout|auth|session|password)([/)_.-]|$)/i;
const SIGN_IN_CODE = new RegExp([
  String.raw`\b(bcrypt|bcryptjs|argon2|jsonwebtoken|iron-session|passport|next-auth|better-auth|lucia)\b`,
  String.raw`@auth\/|@clerk\/|firebase\/auth|\.auth\.(getUser|getSession|getClaims|signIn)`,
  String.raw`\bgetServerSession\(|\bcurrentUser\(`,
  String.raw`cookies\(\)\)?\s*\.get\(\s*["'\x60][^"'\x60]*(session|token|auth|user|jwt)`,
  String.raw`(localStorage|sessionStorage)\.(get|set)Item\(\s*["'\x60][^"'\x60]*(user|token|session|auth)`,
].join("|"), "i");
const SCHEMA_FILE = /(^|\/)schema\.prisma$|\.sql$|(^|\/)schema\.[cm]?[jt]s$/;

/** Whether the app has accounts at all: an auth tool, a signed-in route, a
 * sign-in page or a users table. */
export function appSignIn(input: {
  routes: readonly Pick<RouteFact, "path" | "file" | "authenticated">[];
  stack: Pick<StackReport, "tools">;
  tables: readonly string[];
  archive: { files: readonly { path: string; content: string }[]; truncated: boolean };
}): SignIn {
  if (input.stack.tools.some((t) => t.kind === "auth")) return "present";
  if (input.routes.some((r) => r.authenticated || SIGN_IN_PATH.test(r.path) || SIGN_IN_PATH.test(r.file))) return "present";
  if (input.tables.some((t) => USER_TABLE.test(t.replace(/^public\./, "")))) return "present";
  for (const f of input.archive.files) {
    if (SIGN_IN_PATH.test(f.path) && /\.(t|j)sx?$/.test(f.path)) return "present";
    if (SIGN_IN_CODE.test(f.content)) return "present";
    if (SCHEMA_FILE.test(f.path) && /\bpassword/i.test(f.content)) return "present";
  }
  return input.archive.truncated ? "unknown" : "absent";
}

export type OpenByDesign = { file: string; line: number; reason: string };

// A fixed identity in code (`const DEMO_FARMER_ID = ...`), not an env template.
const DEMO_IDENTITY = /\bconst\s+(DEMO_[A-Z0-9_]*ID)\s*=/;
// The author saying so, in a comment or string, in plain words.
const DECLARED = /\b(there is no|there's no|no) (auth|authentication|login|sign[- ]?in)\b[^.\n]{0,20}\b(in|for) this (app|application|project)\b/i;

/**
 * Where an app with no sign-in says, in its own code, that it is open by
 * design. The census over labeled attempts 3 to 5: apps with no
 * sign-in held 31 true findings and 5 false, so absence alone moves real
 * findings; 4 of the 5 false sat in apps whose code fixes a demo identity or
 * says there is no sign-in. Null unless sign-in is read as absent.
 */
export function openByDesign(input: Parameters<typeof appSignIn>[0]): OpenByDesign | null {
  if (appSignIn(input) !== "absent") return null;
  for (const f of input.archive.files) {
    if (!/\.[cm]?[jt]sx?$/.test(f.path)) continue;
    const lines = f.content.split("\n");
    for (const [i, line] of lines.entries()) {
      const demo = DEMO_IDENTITY.exec(line);
      if (demo) return { file: f.path, line: i + 1, reason: `sets a fixed demo identity (${demo[1]})` };
      if (DECLARED.test(line)) return { file: f.path, line: i + 1, reason: "says there is no sign-in in this app" };
    }
  }
  return null;
}
