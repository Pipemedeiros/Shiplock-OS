import { describe, expect, it } from "vitest";
import {
  isAuthPath,
  isSuspiciousPath,
  computeSignals,
  detect,
  AUTH_ALERT_THRESHOLD,
  AUTH_BLOCK_THRESHOLD,
  SCAN_DISTINCT_THRESHOLD,
  FLOOD_THRESHOLD,
  SESSION_SOURCE_THRESHOLD,
  BLOCK_TTL_LONG_MS,
  BLOCK_TTL_SHORT_MS,
  type EventRow,
  type TrafficSignals,
} from "./detect";

const signals = (over: Partial<TrafficSignals> = {}): TrafficSignals => ({
  authCount: 0,
  distinctScanPaths: 0,
  totalCount: 0,
  capped: false,
  distinctSourcesForSession: 0,
  ...over,
});

describe("isAuthPath", () => {
  it("matches common auth routes", () => {
    for (const p of ["/login", "/signin", "/sign-in", "/register", "/auth", "/api/auth/callback", "/app/auth/session"]) {
      expect(isAuthPath(p)).toBe(true);
    }
  });
  it("does not match ordinary routes", () => {
    for (const p of ["/", "/dashboard", "/api/posts", "/products/authentic-widget"]) {
      expect(isAuthPath(p)).toBe(false);
    }
  });
});

describe("isSuspiciousPath", () => {
  it("flags scanner probe paths", () => {
    for (const p of ["/.env", "/.env.production", "/.git/config", "/wp-admin/", "/wp-login.php", "/phpmyadmin/", "/xmlrpc.php", "/.aws/credentials"]) {
      expect(isSuspiciousPath(p)).toBe(true);
    }
  });
  it("leaves normal paths alone", () => {
    for (const p of ["/", "/environment", "/git-history", "/admin", "/api/users"]) {
      expect(isSuspiciousPath(p)).toBe(false);
    }
  });
});

describe("computeSignals", () => {
  const now = Date.parse("2026-07-14T12:00:00Z");
  const at = (secAgo: number) => new Date(now - secAgo * 1000).toISOString();

  it("counts auth hits only inside the auth window", () => {
    const rows: EventRow[] = [
      { path: "/login", created_at: at(5) },
      { path: "/login", created_at: at(30) },
      { path: "/login", created_at: at(90) }, // outside 60s window
      { path: "/dashboard", created_at: at(5) }, // not an auth path
    ];
    expect(computeSignals(rows, now).authCount).toBe(2);
  });

  it("counts distinct suspicious paths inside the scan window", () => {
    const rows: EventRow[] = [
      { path: "/.env", created_at: at(10) },
      { path: "/.env", created_at: at(11) }, // duplicate — same path
      { path: "/.git/config", created_at: at(12) },
      { path: "/wp-login.php", created_at: at(400) }, // outside 300s window
    ];
    expect(computeSignals(rows, now).distinctScanPaths).toBe(2);
  });

  it("ignores unparseable timestamps", () => {
    const rows: EventRow[] = [{ path: "/login", created_at: "not-a-date" }];
    expect(computeSignals(rows, now).totalCount).toBe(0);
  });
});

describe("detect", () => {
  it("returns none for quiet traffic", () => {
    expect(detect(signals()).action).toBe("none");
  });

  it("alerts (never blocks) on elevated-but-ambiguous auth volume", () => {
    const d = detect(signals({ authCount: AUTH_ALERT_THRESHOLD }));
    expect(d.action).toBe("alert");
    expect(d.severity).toBe("WARNING");
    expect(d.ttlMs).toBe(0);
  });

  it("does not alert just below the alert threshold", () => {
    expect(detect(signals({ authCount: AUTH_ALERT_THRESHOLD - 1 })).action).toBe("none");
  });

  it("blocks credential stuffing at the block threshold (1h)", () => {
    const d = detect(signals({ authCount: AUTH_BLOCK_THRESHOLD }));
    expect(d.action).toBe("block");
    expect(d.ttlMs).toBe(BLOCK_TTL_LONG_MS);
  });

  it("blocks a vulnerability scanner (1h) and outranks auth signals", () => {
    const d = detect(signals({ distinctScanPaths: SCAN_DISTINCT_THRESHOLD, authCount: AUTH_ALERT_THRESHOLD }));
    expect(d.action).toBe("block");
    expect(d.reason).toMatch(/scanning/i);
    expect(d.ttlMs).toBe(BLOCK_TTL_LONG_MS);
  });

  it("blocks a flood (15m)", () => {
    const d = detect(signals({ totalCount: FLOOD_THRESHOLD }));
    expect(d.action).toBe("block");
    expect(d.ttlMs).toBe(BLOCK_TTL_SHORT_MS);
  });

  it("treats a capped fetch as a flood block", () => {
    const d = detect(signals({ capped: true }));
    expect(d.action).toBe("block");
    expect(d.ttlMs).toBe(BLOCK_TTL_SHORT_MS);
  });

  it("alerts on a session used from many sources, and never blocks it", () => {
    const d = detect(signals({ distinctSourcesForSession: SESSION_SOURCE_THRESHOLD }));
    expect(d.action).toBe("alert");
    expect(d.reason).toMatch(/session hijack/i);
    expect(d.ttlMs).toBe(0);
  });

  it("does not flag a session just below the source threshold", () => {
    expect(detect(signals({ distinctSourcesForSession: SESSION_SOURCE_THRESHOLD - 1 })).action).toBe("none");
  });

  it("still blocks (not just alerts) when a hijack signal coincides with brute force", () => {
    const d = detect(signals({ distinctSourcesForSession: SESSION_SOURCE_THRESHOLD, authCount: AUTH_BLOCK_THRESHOLD }));
    expect(d.action).toBe("block");
  });

  it("does not block just below every block threshold", () => {
    const d = detect(
      signals({
        authCount: AUTH_BLOCK_THRESHOLD - 1,
        distinctScanPaths: SCAN_DISTINCT_THRESHOLD - 1,
        totalCount: FLOOD_THRESHOLD - 1,
      })
    );
    expect(d.action).not.toBe("block");
  });
});
