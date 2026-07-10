"use client";

// Real first-scan flow, Design D visuals. No mock data — every field here
// is either user input or the real POST /api/scan response. This route
// previously had no caller anywhere in the app (see plan notes); this is
// the first one, calling the existing, unmodified /api/scan.

import { useState } from "react";
import Link from "next/link";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
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
  const [error, setError] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
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
        body: JSON.stringify({ supabaseUrl, anonKey }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Scan failed — check your project URL and anon key.");
        setPhase("connect");
        return;
      }

      setResult(data as ScanResponse);
      setPhase("report");
    } catch {
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
          <p className="dxd-keynote">
            We only ever ask for your app&apos;s public key — the same credential your own
            frontend already exposes to every visitor. No repo access, no admin tokens, no
            exceptions.
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
            Running the fifteen-check audit against your live app…
          </span>
          <p className="dxd-keynote" style={{ marginTop: 16 }}>
            This takes about a minute. We&apos;re reading your project&apos;s public
            configuration only — zero rows read from your tables.
          </p>
        </div>
      )}

      {phase === "report" && result && (
        <div>
          <div style={{ display: "flex", gap: 28, alignItems: "flex-start", flexWrap: "wrap" }}>
            <p className="dxd-grade dxd-serif" aria-label={`Grade ${result.grade}`}>
              {result.grade}
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
