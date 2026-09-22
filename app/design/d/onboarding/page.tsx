"use client";

// DIRECTION D · ON RETAINER — onboarding, v2.
// Mirrors the REAL product flow (per CLAUDE.md), mocked:
//   1. account — email/password or Google/GitHub OAuth (sign-in only;
//      explicitly not repository access — the real product keeps those
//      grants separate and so does this copy)
//   2. connect — database (Supabase or Firebase) + its public key, the
//      only credential ever asked
//   3. audit — the 15-check first scan, receipts filing live
//   4. report — free-tier truth: grade + every finding named with
//      severity, briefs LOCKED at the API (not blurred in the browser)
//   5. engaged — retainer active; optional deeper access (GitHub App
//      contents:read, Vercel read-only) offered Pro-side, plus the
//      deliberate refusal of Supabase account tokens

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import {
  CHECKS,
  DISCLAIMER,
  FINDINGS,
  MOCK_PROJECT,
  SEVERITY_LABEL,
  TRUST_LINE,
} from "../../_shared/data";
import { LockMark } from "../Brand";

type Phase = "account" | "connect" | "audit" | "report" | "engaged";

const FLAGGED = new Map(FINDINGS.map((f) => [f.checkId, f.severity]));

const BAND_COPY: Record<Phase, { eyebrow: string; title: React.ReactNode }> = {
  account: { eyebrow: "Engagement · step 1 of 3", title: <>Bring us in.</> },
  connect: {
    eyebrow: "Engagement · step 2 of 3",
    title: <>Point us at the stack.</>,
  },
  audit: {
    eyebrow: "Engagement · step 3 of 3",
    title: <>The first audit is running.</>,
  },
  report: { eyebrow: "The first report", title: <>Here is where you stand.</> },
  engaged: {
    eyebrow: "Retainer active",
    title: (
      <>
        From here, <em>we carry it.</em>
      </>
    ),
  },
};

export default function RetainerOnboarding() {
  const [phase, setPhase] = useState<Phase>("account");
  const [done, setDone] = useState(0);
  const [db, setDb] = useState<"supabase" | "firebase">("supabase");
  const [connected, setConnected] = useState<Set<string>>(new Set());
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (phase !== "audit") return;
    timer.current = setInterval(() => {
      setDone((n) => {
        if (n >= CHECKS.length) {
          if (timer.current) clearInterval(timer.current);
          setTimeout(() => setPhase("report"), 800);
          return n;
        }
        return n + 1;
      });
    }, 320);
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [phase]);

  const band = BAND_COPY[phase];

  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/design/d" className="dxd-wordmark">
              <span className="dxd-wordmark-lock">
                <LockMark size={19} />
              </span>
              ShipLock
            </Link>
            <span
              className="dxd-mono"
              style={{ fontSize: 11, letterSpacing: "0.2em", color: "var(--d-muted-light)" }}
            >
              ENGAGEMENT
            </span>
          </nav>
          <div className="dxd-onb-band">
            <p className="dxd-eyebrow">{band.eyebrow}</p>
            <h1 className="dxd-display" style={{ fontSize: "clamp(34px,5.2vw,56px)" }}>
              {band.title}
            </h1>
          </div>
        </div>
      </div>

      <div className="dxd-shell">
        <div className="dxd-onb-card">
          {phase === "account" && (
            <div>
              <div className="dxd-oauth">
                <button
                  type="button"
                  className="dxd-oauth-btn"
                  onClick={() => setPhase("connect")}
                >
                  <span aria-hidden="true">◷</span> Continue with Google
                </button>
                <button
                  type="button"
                  className="dxd-oauth-btn"
                  onClick={() => setPhase("connect")}
                >
                  <span aria-hidden="true">◈</span> Continue with GitHub
                </button>
              </div>
              <p className="dxd-keynote" style={{ margin: "12px 0 0" }}>
                GitHub here is <b>sign-in only</b> — never repository access.
                If you later extend the engagement to source scanning, that is
                a separate, contents-only grant you approve on its own.
              </p>
              <div className="dxd-divider">or with email</div>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  setPhase("connect");
                }}
              >
                <div className="dxd-field">
                  <label htmlFor="dxd-email">Email</label>
                  <input id="dxd-email" type="email" defaultValue="founder@acme-crm.com" />
                </div>
                <div className="dxd-field">
                  <label htmlFor="dxd-pass">Password</label>
                  <input id="dxd-pass" type="password" defaultValue="••••••••••••" />
                </div>
                <button type="submit" className="dxd-btn" style={{ width: "100%" }}>
                  Create the account
                </button>
              </form>
            </div>
          )}

          {phase === "connect" && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                setPhase("audit");
              }}
            >
              <div
                className="dxd-seg"
                role="radiogroup"
                aria-label="Where your data lives"
              >
                <button
                  type="button"
                  role="radio"
                  aria-checked={db === "supabase"}
                  onClick={() => setDb("supabase")}
                >
                  Supabase
                </button>
                <button
                  type="button"
                  role="radio"
                  aria-checked={db === "firebase"}
                  onClick={() => setDb("firebase")}
                >
                  Firebase
                </button>
              </div>
              <div className="dxd-field">
                <label htmlFor="dxd-url">
                  {db === "supabase" ? "Supabase project URL" : "Firebase project ID"}
                </label>
                <input
                  id="dxd-url"
                  key={`url-${db}`}
                  defaultValue={
                    db === "supabase"
                      ? MOCK_PROJECT.supabaseUrl
                      : MOCK_PROJECT.firebaseProjectId
                  }
                  spellCheck={false}
                />
              </div>
              <div className="dxd-field">
                <label htmlFor="dxd-key">
                  {db === "supabase" ? "Anon key" : "Web API key"} — the
                  public one, and the only credential we&apos;ll ever ask for
                </label>
                <input
                  id="dxd-key"
                  key={`key-${db}`}
                  defaultValue={
                    db === "supabase"
                      ? MOCK_PROJECT.anonKeyPreview
                      : MOCK_PROJECT.webApiKeyPreview
                  }
                  spellCheck={false}
                />
              </div>
              <p className="dxd-keynote">{TRUST_LINE}</p>
              <button type="submit" className="dxd-btn" style={{ width: "100%" }}>
                Begin the first audit
              </button>
            </form>
          )}

          {phase === "audit" && (
            <div>
              <span className="dxd-working" role="status">
                <i />
                <i />
                <i />
                Filing receipt {Math.min(done + 1, CHECKS.length)} of{" "}
                {CHECKS.length} · {MOCK_PROJECT.appUrl}
              </span>
              <ul className="dxd-auditlist" role="log" aria-live="polite">
                {CHECKS.slice(0, done).map((c) => {
                  const sev = FLAGGED.get(c.id);
                  return (
                    <li key={c.id}>
                      <span className="dxd-audit-name">
                        {String(c.id).padStart(2, "0")} · {c.name.toLowerCase()}
                      </span>
                      {sev ? (
                        <span className={`dxd-chip dxd-chip-${sev}`}>needs you</span>
                      ) : (
                        <span className="dxd-chip dxd-chip-verified">holding</span>
                      )}
                    </li>
                  );
                })}
              </ul>
              <button
                type="button"
                className="dxd-btn-quiet"
                style={{ marginTop: 16 }}
                onClick={() => {
                  setDone(CHECKS.length);
                  setPhase("report");
                }}
              >
                Skip to the report →
              </button>
            </div>
          )}

          {phase === "report" && (
            <div>
              <div style={{ display: "flex", gap: 28, alignItems: "flex-start", flexWrap: "wrap" }}>
                <p className="dxd-grade dxd-serif" aria-label="Grade C">
                  C
                </p>
                <div style={{ flex: 1, minWidth: 240 }}>
                  <p style={{ margin: "8px 0 6px", fontWeight: 600, fontSize: 16.5 }}>
                    Four findings. One is serious. Every one is named below —
                    that part is free.
                  </p>
                  <p style={{ margin: 0, color: "var(--d-muted)", fontSize: 14.5, lineHeight: 1.65 }}>
                    The step-by-step briefs, the SQL, and the AI-tool prompts
                    are prepared and held on retainer.
                  </p>
                </div>
              </div>

              <div style={{ margin: "22px 0 8px" }}>
                {FINDINGS.map((f) => (
                  <div
                    key={f.id}
                    style={{
                      display: "flex",
                      alignItems: "baseline",
                      gap: 14,
                      padding: "11px 2px",
                      borderTop: "1px solid var(--d-line)",
                      flexWrap: "wrap",
                    }}
                  >
                    <span className={`dxd-chip dxd-chip-${f.severity}`}>
                      {SEVERITY_LABEL[f.severity]}
                    </span>
                    <span style={{ flex: 1, fontWeight: 600, fontSize: 14.5, minWidth: 180 }}>
                      {f.title}
                    </span>
                    <span className="dxd-locked-brief">Brief on retainer</span>
                  </div>
                ))}
              </div>

              <p className="dxd-keynote" style={{ margin: "10px 0 22px" }}>
                Locked at the API, not blurred in the browser — the briefs
                never leave the vault until you engage. Check the network tab
                if you like; that&apos;s rather the point.
              </p>

              <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
                <button
                  type="button"
                  className="dxd-btn"
                  onClick={() => setPhase("engaged")}
                >
                  Join the founder pilot
                </button>
                <Link href="/design/d/dashboard" className="dxd-btn-quiet">
                  Preview the board first
                </Link>
              </div>
            </div>
          )}

          {phase === "engaged" && (
            <div>
              <p style={{ margin: "0 0 4px", fontWeight: 600, fontSize: 16.5 }}>
                The retainer is active. The briefs are unlocked.
              </p>
              <p style={{ margin: "0 0 20px", color: "var(--d-muted)", fontSize: 14.5, lineHeight: 1.65 }}>
                Optional: extend the engagement. Each grant is separate,
                narrow, and revocable — and we archive its findings the moment
                you disconnect.
              </p>

              <div className="dxd-connect-card">
                <div>
                  <h4>GitHub — source scanning</h4>
                  <p>
                    Dependency CVEs and risky source patterns, caught before
                    they deploy.
                  </p>
                  <span className="dxd-scope">
                    scope: contents read-only · per-repo · revocable
                  </span>
                </div>
                <span className="dxd-connect-cta">
                  {connected.has("github") ? (
                    <span className="dxd-chip dxd-chip-verified">Connected</span>
                  ) : (
                    <button
                      type="button"
                      className="dxd-btn dxd-btn-ghost"
                      onClick={() => setConnected((s) => new Set(s).add("github"))}
                    >
                      Connect
                    </button>
                  )}
                </span>
              </div>

              <div className="dxd-connect-card">
                <div>
                  <h4>Vercel — environment audit</h4>
                  <p>
                    Flags server secrets exposed to the client bundle. We
                    never store or log a variable&apos;s value — key and
                    reason only.
                  </p>
                  <span className="dxd-scope">
                    scope: read-only · selected projects only
                  </span>
                </div>
                <span className="dxd-connect-cta">
                  {connected.has("vercel") ? (
                    <span className="dxd-chip dxd-chip-verified">Connected</span>
                  ) : (
                    <button
                      type="button"
                      className="dxd-btn dxd-btn-ghost"
                      onClick={() => setConnected((s) => new Set(s).add("vercel"))}
                    >
                      Connect
                    </button>
                  )}
                </span>
              </div>

              <p className="dxd-policy-note" style={{ marginTop: 18 }}>
                You won&apos;t find a database account-token box here —
                Supabase or Firebase. Those tokens can&apos;t be narrowly
                scoped — they would hand us your whole account — so we
                refuse to ask for them. The same standard we hold everyone
                else to.
              </p>

              <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 22 }}>
                <Link href="/design/d/dashboard" className="dxd-btn">
                  Open the coverage board
                </Link>
              </div>
            </div>
          )}
        </div>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span>
          </span>
          <span>{DISCLAIMER}</span>
        </footer>
      </div>
    </main>
  );
}
