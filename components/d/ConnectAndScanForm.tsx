"use client";

// Real first-scan flow, Design D visuals. No mock data — every field here
// is either user input or the real POST /api/scan response. This route
// previously had no caller anywhere in the app (see plan notes); this is
// the first one, calling the existing, unmodified /api/scan.

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { track } from "@/lib/analytics";
import { DecryptText } from "@/components/d/bits";
import type { ScanResponse, PreviewIssue, FullIssue, Severity } from "@/lib/types";

type Phase = "connect" | "scanning" | "report";

const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  WARNING: "Warning",
  INFO: "Info",
};

const SEVERITY_CHIP: Record<Severity, string> = {
  CRITICAL: "dxd-chip-critical",
  WARNING: "dxd-chip-medium",
  INFO: "dxd-chip-low",
};

function isFullIssue(issue: PreviewIssue | FullIssue): issue is FullIssue {
  return "fix" in issue;
}

export function ConnectAndScanForm() {
  const [phase, setPhase] = useState<Phase>("connect");
  const [supabaseUrl, setSupabaseUrl] = useState("");
  const [anonKey, setAnonKey] = useState("");
  const [appUrl, setAppUrl] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  // The report is the conversion moment — bring it into view the instant it
  // exists instead of leaving the grade below the fold.
  useEffect(() => {
    if (phase === "report") {
      reportRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [phase]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    // Counts/booleans only — never the URL or key (lib/analytics.ts rule).
    track("scan_started", { has_app_url: Boolean(appUrl) });
    setError("");
    setPhase("scanning");

    try {
      const supabase = getSupabaseBrowser();
      const {
        data: { session },
      } = await supabase.auth.getSession();

      const res = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(session?.access_token
            ? { Authorization: `Bearer ${session.access_token}` }
            : {}),
        },
        body: JSON.stringify({ supabaseUrl, anonKey, ...(appUrl ? { appUrl } : {}) }),
      });

      const data = await res.json();

      if (!res.ok) {
        track("scan_failed", { status: res.status });
        setError(data.error ?? "Scan failed — check your project URL and anon key.");
        setPhase("connect");
        return;
      }

      const scan = data as ScanResponse;
      track("scan_completed", {
        issue_count: scan.issues.length,
        critical_count: scan.issues.filter((i) => i.severity === "CRITICAL").length,
      });
      setResult(scan);
      setPhase("report");
    } catch {
      track("scan_failed", { status: 0 });
      setError("Couldn't reach the server. Try again in a moment.");
      setPhase("connect");
    }
  }

  return (
    <div className="dxd-onb-card">
      {phase === "connect" && (
        <form onSubmit={handleSubmit}>
          <div className="dxd-field">
            <label htmlFor="dxd-supabase-url">Supabase project URL</label>
            <input
              id="dxd-supabase-url"
              type="url"
              required
              placeholder="https://xyzcompany.supabase.co"
              value={supabaseUrl}
              onChange={(e) => setSupabaseUrl(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="dxd-field">
            <label htmlFor="dxd-anon-key">
              Anon key — the public one, and the only credential we&apos;ll ever ask for
            </label>
            <input
              id="dxd-anon-key"
              type="text"
              required
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6..."
              value={anonKey}
              onChange={(e) => setAnonKey(e.target.value)}
              spellCheck={false}
            />
          </div>
          <div className="dxd-field">
            <label htmlFor="dxd-app-url">
              Your app&apos;s live URL — optional, but it makes the audit about your app
            </label>
            <input
              id="dxd-app-url"
              type="url"
              placeholder="https://yourapp.com"
              value={appUrl}
              onChange={(e) => setAppUrl(e.target.value)}
              spellCheck={false}
            />
          </div>
          <p className="dxd-keynote">
            We only ever ask for your app&apos;s public key and, optionally, its public URL —
            already public either way, not credentials. No repo access, no admin tokens, no
            exceptions. Skip the URL and we still run 14 of 16 checks against your database; add
            it and we also look at your <em>deployed app</em> for an exposed package.json or .env
            the Supabase URL alone can&apos;t see. Either way we grade honestly: anything that&apos;s
            just a Supabase platform default, we label as a note — never dress it up as a red alarm.
          </p>
          {error && (
            <p style={{ fontSize: 13, color: "var(--d-signal)", margin: "0 0 16px" }}>{error}</p>
          )}
          <button type="submit" className="dxd-btn" style={{ width: "100%" }}>
            Begin the first audit
          </button>
        </form>
      )}

      {phase === "scanning" && (
        <div>
          <span className="dxd-working" role="status">
            <i />
            <i />
            <i />
            Running the sixteen-check audit against your live app…
          </span>
          <p className="dxd-keynote" style={{ marginTop: 16 }}>
            This takes about a minute. We&apos;re reading your project&apos;s public
            configuration only — zero rows read from your tables.
          </p>
        </div>
      )}

      {phase === "report" && result && (
        <div ref={reportRef} style={{ scrollMarginTop: 24 }}>
          <div style={{ display: "flex", gap: 28, alignItems: "flex-start", flexWrap: "wrap" }}>
            <p
              className="dxd-grade dxd-serif"
              aria-label={`${result.issues.length} open finding${result.issues.length === 1 ? "" : "s"}`}
            >
              <DecryptText text={String(result.issues.length)} duration={900} />
            </p>
            <div style={{ flex: 1, minWidth: 240 }}>
              <p style={{ margin: "8px 0 6px", fontWeight: 600, fontSize: 16.5 }}>
                {result.summary}
              </p>
              {!result.isPaid && (
                <p style={{ margin: 0, color: "var(--d-muted)", fontSize: 14.5, lineHeight: 1.65 }}>
                  The step-by-step briefs, the SQL, and the AI-tool prompts are prepared and
                  held on retainer.
                </p>
              )}
              {!result.appUrlChecked && (
                <p style={{ margin: "6px 0 0", color: "var(--d-muted)", fontSize: 13.5, lineHeight: 1.6 }}>
                  This scan didn&apos;t include your app&apos;s live URL, so 2 of 16 checks
                  (exposed package.json, exposed .env) couldn&apos;t look at anything real. Add
                  it on your next scan for full coverage.
                </p>
              )}
            </div>
          </div>

          <div style={{ margin: "22px 0 8px" }}>
            {result.issues.length === 0 && (
              <p style={{ color: "var(--d-verified)", fontWeight: 600, padding: "11px 2px" }}>
                No open findings. Every check held.
              </p>
            )}
            {result.issues.map((issue, i) => (
              <div key={`${issue.title}-${i}`}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "baseline",
                    gap: 14,
                    padding: "11px 2px",
                    borderTop: "1px solid var(--d-line)",
                    flexWrap: "wrap",
                  }}
                >
                  <span className={`dxd-chip ${SEVERITY_CHIP[issue.severity]}`}>
                    {SEVERITY_LABEL[issue.severity]}
                  </span>
                  <span style={{ flex: 1, fontWeight: 600, fontSize: 14.5, minWidth: 180 }}>
                    {issue.title}
                  </span>
                  {!isFullIssue(issue) && (
                    <span className="dxd-locked-brief">Brief on retainer</span>
                  )}
                </div>
                <p style={{ margin: "0 0 4px 2px", color: "var(--d-muted)", fontSize: 13.5 }}>
                  {issue.consequence}
                </p>
                {isFullIssue(issue) && (
                  <div className="dxd-brief" style={{ marginBottom: 12 }}>
                    <p className="dxd-brief-title">The fix</p>
                    <p style={{ fontSize: 14, lineHeight: 1.6 }}>{issue.fix}</p>
                    {issue.codefix && (
                      <>
                        <pre className="dxd-code">{issue.codefix.prompt}</pre>
                        <p className="dxd-keynote" style={{ margin: "8px 0 0" }}>
                          {issue.codefix.description} — {issue.codefix.file}
                        </p>
                      </>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>

          {!result.isPaid && (
            <p className="dxd-keynote" style={{ margin: "10px 0 22px" }}>
              Locked at the API, not blurred in the browser — the briefs never leave the vault
              until you engage. Check the network tab if you like; that&apos;s rather the
              point.
            </p>
          )}

          {result.monitoringEnrolled && (
            <p
              className="dxd-mono"
              style={{
                margin: "0 0 20px",
                fontSize: 12.5,
                lineHeight: 1.7,
                color: "var(--d-ink)",
                borderLeft: "2px solid var(--d-bronze)",
                paddingLeft: 14,
              }}
            >
              <span style={{ color: "var(--d-bronze)" }}>● The watch is now active.</span>{" "}
              This project is enrolled in continuous monitoring — hourly critical checks and a
              full deep audit every 48 hours. You&apos;ll only hear from us when something new
              appears; the log of every pass lives on your dashboard.
            </p>
          )}

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <Link href="/dashboard" className="dxd-btn">
              Continue to your dashboard
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
