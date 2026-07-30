import { describe, expect, it } from "vitest";
import {
  analyzeAuthEvents,
  detectBruteForce,
  detectCredentialStuffing,
  detectSignupBurst,
  detectTakeoverSequence,
  normaliseAuthEvent,
  type AuthAction,
  type AuthEvent,
} from "./authEvents";

const T0 = new Date("2026-07-30T12:00:00Z").getTime();
const ev = (action: AuthAction, actorId: string | null, sourceId: string | null, minute = 0): AuthEvent => ({
  at: new Date(T0 + minute * 60_000),
  action,
  actorId,
  sourceId,
});

const many = (n: number, fn: (i: number) => AuthEvent) => Array.from({ length: n }, (_, i) => fn(i));

describe("E5 — credential stuffing", () => {
  it("fires on failures SPREAD across many accounts from one source", () => {
    const out = detectCredentialStuffing(many(20, (i) => ev("login_failed", `user${i}`, "src-a", i)));
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].consequence).toContain("reused theirs");
  });

  // The shape is spread. Concentration on one account is a locked-out person.
  it("does NOT fire when many failures hit a single account", () => {
    expect(detectCredentialStuffing(many(30, (i) => ev("login_failed", "user1", "src-a", i)))).toEqual([]);
  });

  it("does not fire on a handful of failures across a few accounts", () => {
    expect(detectCredentialStuffing(many(6, (i) => ev("login_failed", `user${i}`, "src-a", i)))).toEqual([]);
  });

  it("does not fire when spread across many sources — that is normal traffic", () => {
    expect(detectCredentialStuffing(many(20, (i) => ev("login_failed", `user${i}`, `src-${i}`, i)))).toEqual([]);
  });

  it("ignores successful logins entirely", () => {
    expect(detectCredentialStuffing(many(40, (i) => ev("login", `user${i}`, "src-a", i)))).toEqual([]);
  });

  it("tells them to check for SUCCESSFUL logins from the same source", () => {
    const out = detectCredentialStuffing(many(20, (i) => ev("login_failed", `user${i}`, "src-a", i)));
    expect(out[0].consequence).toContain("SUCCEEDED");
  });
});

describe("E7 — brute force on one account", () => {
  it("fires on concentrated failures against one account", () => {
    const out = detectBruteForce(many(25, (i) => ev("login_failed", "user1", "src-a", i)));
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
  });

  // Far more often a locked-out customer than an attacker; the copy must not
  // alarm someone about their own user.
  it("says plainly that a single source is usually a locked-out person", () => {
    const out = detectBruteForce(many(25, (i) => ev("login_failed", "user1", "src-a", i)));
    expect(out[0].consequence).toContain("usually a real person locked out");
  });

  it("escalates to CRITICAL when many sources target one account", () => {
    const out = detectBruteForce(many(25, (i) => ev("login_failed", "user1", `src-${i % 8}`, i)));
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].title).toContain("distributed");
  });

  it("does not fire below the threshold", () => {
    expect(detectBruteForce(many(10, (i) => ev("login_failed", "user1", "src-a", i)))).toEqual([]);
  });
});

describe("E6 — takeover sequence", () => {
  const takeover = [
    ...many(5, (i) => ev("login_failed", "user1", "src-evil", i)),
    ev("login", "user1", "src-evil", 6),
    ev("password_changed", "user1", "src-evil", 8),
  ];

  it("fires on failures, then success, then a password change", () => {
    const out = detectTakeoverSequence(takeover);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
  });

  // Each event is normal alone; only the order makes it a finding.
  it("explains that the ORDER is the signal", () => {
    expect(detectTakeoverSequence(takeover)[0].consequence).toContain("unremarkable alone");
  });

  it("warns that the real owner can no longer report it", () => {
    expect(detectTakeoverSequence(takeover)[0].consequence).toContain("can no longer log in to tell you");
  });

  it("does NOT fire on a normal password change after a clean login", () => {
    expect(
      detectTakeoverSequence([ev("login", "user1", "src-ok", 0), ev("password_changed", "user1", "src-ok", 1)])
    ).toEqual([]);
  });

  it("does not fire when the failures came from a different source", () => {
    expect(
      detectTakeoverSequence([
        ...many(5, (i) => ev("login_failed", "user1", "src-other", i)),
        ev("login", "user1", "src-owner", 6),
        ev("password_changed", "user1", "src-owner", 8),
      ])
    ).toEqual([]);
  });

  it("does not fire when the password change is long after the login", () => {
    expect(
      detectTakeoverSequence([
        ...many(5, (i) => ev("login_failed", "user1", "src-evil", i)),
        ev("login", "user1", "src-evil", 6),
        ev("password_changed", "user1", "src-evil", 600),
      ])
    ).toEqual([]);
  });

  it("reports one finding per account, not one per matching event", () => {
    expect(detectTakeoverSequence([...takeover, ev("password_changed", "user1", "src-evil", 9)])).toHaveLength(1);
  });
});

describe("signup burst", () => {
  it("fires on automated account creation from one source", () => {
    const out = detectSignupBurst(many(30, (i) => ev("signup", `user${i}`, "src-a", i % 50)));
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
  });

  it("connects it to the tenant-isolation risk rather than overstating it alone", () => {
    const out = detectSignupBurst(many(30, (i) => ev("signup", `user${i}`, "src-a", i % 50)));
    expect(out[0].consequence).toContain("your bill rather than your data");
  });

  it("does not fire on organic signups from many sources", () => {
    expect(detectSignupBurst(many(30, (i) => ev("signup", `user${i}`, `src-${i}`, i)))).toEqual([]);
  });
});

describe("analyzeAuthEvents", () => {
  it("returns nothing for an empty log", () => {
    expect(analyzeAuthEvents([])).toEqual([]);
  });

  // A quiet week must look quiet. Silence is the default everywhere else in the
  // product and this is no exception.
  it("returns nothing for ordinary activity", () => {
    const normal = [
      ...many(20, (i) => ev("login", `user${i}`, `src-${i}`, i)),
      ...many(3, (i) => ev("login_failed", `user${i}`, `src-${i}`, i)),
      ...many(4, (i) => ev("signup", `new${i}`, `src-${i}`, i)),
      ev("password_changed", "user1", "src-1", 30),
    ];
    expect(analyzeAuthEvents(normal)).toEqual([]);
  });

  it("puts the takeover first, since it is the one to act on immediately", () => {
    const events = [
      ...many(20, (i) => ev("login_failed", `victim${i}`, "src-evil", i)),
      ...many(5, (i) => ev("login_failed", "user1", "src-evil", i)),
      ev("login", "user1", "src-evil", 6),
      ev("password_changed", "user1", "src-evil", 8),
    ];
    expect(analyzeAuthEvents(events)[0].id).toContain("takeover");
  });

  it("produces stable ids for the diff engine", () => {
    const events = many(20, (i) => ev("login_failed", `user${i}`, "src-a", i));
    expect(analyzeAuthEvents(events).map((f) => f.id)).toEqual(analyzeAuthEvents(events).map((f) => f.id));
  });
});

describe("normaliseAuthEvent", () => {
  it("maps Supabase's action names", () => {
    const cases: [string, AuthAction][] = [
      ["login", "login"],
      ["user_signedup", "signup"],
      ["login_failed", "login_failed"],
      ["invalid_credentials", "login_failed"],
      ["user_updated_password", "password_changed"],
      ["token_refreshed", "token_refreshed"],
      ["user_recovery_requested", "password_recovery"],
    ];
    for (const [action, expected] of cases) {
      expect(normaliseAuthEvent({ action, created_at: "2026-07-30T12:00:00Z" })?.action, action).toBe(expected);
    }
  });

  // The endpoint is experimental and its field names have moved.
  it("accepts several timestamp field names", () => {
    for (const key of ["created_at", "timestamp", "time"]) {
      expect(normaliseAuthEvent({ action: "login", [key]: "2026-07-30T12:00:00Z" })).not.toBeNull();
    }
  });

  it("reads nested metadata", () => {
    const e = normaliseAuthEvent({ metadata: { action: "login", timestamp: "2026-07-30T12:00:00Z" } });
    expect(e?.action).toBe("login");
  });

  it("maps an unknown action to `other` rather than throwing", () => {
    expect(normaliseAuthEvent({ action: "some_future_event", created_at: "2026-07-30T12:00:00Z" })?.action).toBe("other");
  });

  // A row we cannot place in time would corrupt a sequence rather than merely be
  // missing from it, so it is dropped.
  it("DROPS a row with no usable timestamp", () => {
    expect(normaliseAuthEvent({ action: "login" })).toBeNull();
    expect(normaliseAuthEvent({ action: "login", created_at: "not a date" })).toBeNull();
  });

  it("tolerates missing actor and source", () => {
    const e = normaliseAuthEvent({ action: "login", created_at: "2026-07-30T12:00:00Z" });
    expect(e?.actorId).toBeNull();
    expect(e?.sourceId).toBeNull();
  });

  it("never fires a detector on rows with no actor or source", () => {
    const events = many(40, () =>
      normaliseAuthEvent({ action: "login_failed", created_at: "2026-07-30T12:00:00Z" })!
    );
    expect(analyzeAuthEvents(events)).toEqual([]);
  });
});
