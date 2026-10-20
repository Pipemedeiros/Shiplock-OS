import type { Severity } from "@/lib/types";

// E5–E7 — runtime attack detection from Supabase's own auth audit log.
//
// Why this matters commercially: it is the only attack detection in the product
// that needs NO installation. The edge snippet gives sub-second blocking, but it
// is a step the customer has to take, and steps are where activation dies.
// Supabase already records every authentication event on the customer's behalf,
// and the Management API can read it — so credential stuffing and account
// takeover become detectable the moment they connect Supabase, with nothing else
// asked of them.
//
// DETECTION PHILOSOPHY, which is what makes this shippable rather than a
// pager-in-a-box: these detectors describe a SHAPE, not a threshold crossing. A
// single failed login is a person mistyping a password. Forty failures across
// thirty-eight different accounts from one address in ten minutes is not, and no
// legitimate flow produces it. Every rule below requires the shape — spread
// across accounts, concentration in a source, or a sequence — and never fires on
// volume alone, because volume alone is how a security product earns its way
// into a mail filter.
//
// PURE. The fetcher lives elsewhere; everything here is a function of its input,
// so the judgement can be tested exhaustively without a customer's log stream.

export type AuthAction =
  | "login"
  | "login_failed"
  | "signup"
  | "password_recovery"
  | "password_changed"
  | "user_deleted"
  | "token_refreshed"
  | "other";

export interface AuthEvent {
  /** When it happened. */
  at: Date;
  action: AuthAction;
  /** Pseudonymous actor id — an account identifier, never an email. */
  actorId: string | null;
  /** Source address, already hashed upstream. Never a raw IP at rest. */
  sourceId: string | null;
}

export interface RuntimeFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
  /** Facts behind the judgement, for the evidence trail. */
  evidence: string[];
}

// Shape thresholds. Set to describe a pattern no legitimate flow produces,
// rather than to be sensitive.
const STUFFING_MIN_FAILURES = 15;
const STUFFING_MIN_DISTINCT_ACCOUNTS = 8;
const BRUTE_FORCE_MIN_FAILURES = 20;
const SIGNUP_BURST_MIN = 25;
const TAKEOVER_WINDOW_MS = 30 * 60 * 1000;

function within(events: AuthEvent[], windowMs: number): AuthEvent[] {
  if (events.length === 0) return [];
  const newest = Math.max(...events.map((e) => e.at.getTime()));
  return events.filter((e) => newest - e.at.getTime() <= windowMs);
}

function countBy<T>(items: T[], key: (item: T) => string | null): Map<string, number> {
  const out = new Map<string, number>();
  for (const item of items) {
    const k = key(item);
    if (k === null) continue;
    out.set(k, (out.get(k) ?? 0) + 1);
  }
  return out;
}

/**
 * E5 — credential stuffing.
 *
 * The distinguishing shape is SPREAD: one source failing against many different
 * accounts. A person who forgot their password fails repeatedly against ONE
 * account, which is why the distinct-account count carries the rule and the raw
 * failure count only qualifies it.
 */
export function detectCredentialStuffing(events: AuthEvent[]): RuntimeFinding[] {
  const failures = events.filter((e) => e.action === "login_failed");
  const bySource = new Map<string, AuthEvent[]>();
  for (const e of failures) {
    if (!e.sourceId) continue;
    bySource.set(e.sourceId, [...(bySource.get(e.sourceId) ?? []), e]);
  }

  const out: RuntimeFinding[] = [];
  for (const [sourceId, sourceFailures] of bySource) {
    const accounts = new Set(sourceFailures.map((e) => e.actorId).filter(Boolean));
    if (sourceFailures.length < STUFFING_MIN_FAILURES) continue;
    if (accounts.size < STUFFING_MIN_DISTINCT_ACCOUNTS) continue;

    out.push({
      id: `runtime:credential_stuffing:${sourceId}`,
      severity: "CRITICAL",
      title: `Someone is testing stolen passwords against your users`,
      consequence:
        `One source produced ${sourceFailures.length} failed sign-ins against ${accounts.size} different accounts. ` +
        `That shape is not someone forgetting a password; a real person fails repeatedly against their OWN account. Trying many different accounts from one place is what credential stuffing looks like: someone is replaying a password list leaked from another service to see which of your users reused theirs. ` +
        `Some of them will have. The accounts that matter are the ones where a login SUCCEEDED from this source, so that is the first thing to check. ` +
        `Turning on rate limiting at your auth provider, and requiring a second factor for accounts with elevated access, are what actually stop this.`,
      evidence: [
        `${sourceFailures.length} failed sign-ins from one source`,
        `${accounts.size} distinct accounts targeted`,
      ],
    });
  }
  return out;
}

/**
 * E7 — brute force against one account.
 *
 * The inverse shape of stuffing: concentration rather than spread. Reported at
 * WARNING because it is far more often a locked-out user than an attacker, and
 * the copy says so rather than alarming someone about their own customer.
 */
export function detectBruteForce(events: AuthEvent[]): RuntimeFinding[] {
  const failures = events.filter((e) => e.action === "login_failed");
  const byAccount = countBy(failures, (e) => e.actorId);

  const out: RuntimeFinding[] = [];
  for (const [actorId, count] of byAccount) {
    if (count < BRUTE_FORCE_MIN_FAILURES) continue;
    const sources = new Set(
      failures.filter((e) => e.actorId === actorId).map((e) => e.sourceId).filter(Boolean)
    );
    // Many sources against one account is a distributed attempt, which is a
    // different and more serious thing than one person mistyping.
    const distributed = sources.size >= 5;
    out.push({
      id: `runtime:brute_force:${actorId}`,
      severity: distributed ? "CRITICAL" : "WARNING",
      title: distributed
        ? `One account is under a distributed password attack`
        : `One account has an unusual number of failed sign-ins`,
      consequence: distributed
        ? `A single account received ${count} failed sign-ins from ${sources.size} different sources. Multiple sources working on one account means this is deliberate and coordinated rather than someone locked out. If this account has elevated access, treat it as the priority: force a password reset and require a second factor before anything else.`
        : `A single account received ${count} failed sign-ins. This is usually a real person locked out of their own account rather than an attack, and we are telling you mainly so it is not a surprise if they contact support. It is worth a look if this account has elevated access, or if you see a successful sign-in from an unfamiliar source afterwards.`,
      evidence: [`${count} failed sign-ins on one account`, `${sources.size} distinct sources`],
    });
  }
  return out;
}

/**
 * E6 — account takeover sequence.
 *
 * A password change immediately following a failed-then-successful login from
 * the same source is the classic takeover fingerprint: get in, then lock the
 * owner out. The SEQUENCE is the signal — each event alone is completely normal.
 */
export function detectTakeoverSequence(events: AuthEvent[]): RuntimeFinding[] {
  const byAccount = new Map<string, AuthEvent[]>();
  for (const e of events) {
    if (!e.actorId) continue;
    byAccount.set(e.actorId, [...(byAccount.get(e.actorId) ?? []), e]);
  }

  const out: RuntimeFinding[] = [];
  for (const [actorId, accountEvents] of byAccount) {
    const ordered = [...accountEvents].sort((a, b) => a.at.getTime() - b.at.getTime());

    for (let i = 0; i < ordered.length; i++) {
      if (ordered[i].action !== "password_changed") continue;
      const changedAt = ordered[i].at.getTime();

      const priorLogin = ordered.find(
        (e) =>
          e.action === "login" &&
          changedAt - e.at.getTime() >= 0 &&
          changedAt - e.at.getTime() <= TAKEOVER_WINDOW_MS
      );
      if (!priorLogin) continue;

      const priorFailures = ordered.filter(
        (e) =>
          e.action === "login_failed" &&
          e.sourceId === priorLogin.sourceId &&
          priorLogin.at.getTime() - e.at.getTime() >= 0 &&
          priorLogin.at.getTime() - e.at.getTime() <= TAKEOVER_WINDOW_MS
      );
      if (priorFailures.length < 3) continue;

      out.push({
        id: `runtime:takeover_sequence:${actorId}`,
        severity: "CRITICAL",
        title: `An account may have been taken over`,
        consequence:
          `One account shows the sequence an account takeover leaves behind: ${priorFailures.length} failed sign-ins, then a successful one from the same source, then a password change within ${Math.round(TAKEOVER_WINDOW_MS / 60000)} minutes. ` +
          `Each of those events is unremarkable alone: people mistype passwords and then change them. In this order, from one source, it is what happens when someone guesses their way in and then locks the owner out. ` +
          `This is the one finding in the product worth acting on before you finish reading: if it is real, the legitimate owner can no longer log in to tell you. Check whether that password change came from the account owner, and if you cannot confirm it quickly, reset the session.`,
        evidence: [
          `${priorFailures.length} failed sign-ins, then success, from one source`,
          `password changed within ${Math.round(TAKEOVER_WINDOW_MS / 60000)} minutes`,
        ],
      });
      break; // one finding per account
    }
  }
  return out;
}

/**
 * Automated signup abuse — the amplifier the graph's tenant-isolation path cares
 * about, because open signups turn "any user can read everything" into "anyone
 * can".
 */
export function detectSignupBurst(events: AuthEvent[], windowMs = 60 * 60 * 1000): RuntimeFinding[] {
  const signups = within(
    events.filter((e) => e.action === "signup"),
    windowMs
  );
  const bySource = countBy(signups, (e) => e.sourceId);

  const out: RuntimeFinding[] = [];
  for (const [sourceId, count] of bySource) {
    if (count < SIGNUP_BURST_MIN) continue;
    out.push({
      id: `runtime:signup_burst:${sourceId}`,
      severity: "WARNING",
      title: `One source is creating accounts automatically`,
      consequence:
        `${count} accounts were created from a single source within an hour. That is automation, not people. ` +
        `On its own it is usually spam or someone farming free-tier usage, and the cost is your bill rather than your data. It becomes serious if any endpoint returns more than the caller's own rows to a signed-in user, because then a free account is all an attacker needs, which is exactly the combination we look for elsewhere. ` +
        `Requiring email confirmation before an account can do anything is the cheapest thing that stops this.`,
      evidence: [`${count} signups from one source within the hour`],
    });
  }
  return out;
}

/** All runtime detectors, in one call. */
export function analyzeAuthEvents(events: AuthEvent[]): RuntimeFinding[] {
  if (events.length === 0) return [];
  return [
    ...detectTakeoverSequence(events),
    ...detectCredentialStuffing(events),
    ...detectBruteForce(events),
    ...detectSignupBurst(events),
  ];
}

/**
 * Maps a raw Supabase audit-log row to our shape.
 *
 * Tolerant by design: the Management API's log endpoint is experimental and its
 * field names have moved. An unrecognised action becomes `other` (and is simply
 * never matched by a detector) rather than throwing — but a row we cannot place
 * in TIME is dropped, because every detector reasons about ordering and windows,
 * and a row with a wrong timestamp would corrupt a sequence rather than merely
 * be missing from it.
 */
export function normaliseAuthEvent(raw: Record<string, unknown>): AuthEvent | null {
  const rawAt =
    raw.created_at ?? raw.timestamp ?? raw.time ?? (raw.metadata as Record<string, unknown>)?.timestamp;
  const at =
    typeof rawAt === "string" || typeof rawAt === "number" ? new Date(rawAt) : null;
  if (!at || Number.isNaN(at.getTime())) return null;

  const rawAction = String(
    raw.action ?? raw.event ?? (raw.metadata as Record<string, unknown>)?.action ?? ""
  ).toLowerCase();

  const action: AuthAction = /login_failed|invalid_credentials|failed/.test(rawAction)
    ? "login_failed"
    : /user_signedup|signup|register/.test(rawAction)
      ? "signup"
      : /password_updated|password_changed|user_updated_password/.test(rawAction)
        ? "password_changed"
        : /recovery|reset/.test(rawAction)
          ? "password_recovery"
          : /token_refreshed|refresh/.test(rawAction)
            ? "token_refreshed"
            : /user_deleted|delete/.test(rawAction)
              ? "user_deleted"
              : /login|signedin|signed_in/.test(rawAction)
                ? "login"
                : "other";

  const actorId = raw.actor_id ?? raw.user_id ?? (raw.actor as Record<string, unknown>)?.id;
  const sourceId = raw.source_id ?? raw.ip_address ?? raw.remote_addr;

  return {
    at,
    action,
    actorId: typeof actorId === "string" ? actorId : null,
    sourceId: typeof sourceId === "string" ? sourceId : null,
  };
}
