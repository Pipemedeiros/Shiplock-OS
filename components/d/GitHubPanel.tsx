"use client";

// Source-scanning panel (GitHub). Connect is a GET redirect (plain link);
// scan/disconnect are POSTs to the Pro-gated deep routes, which authenticate
// from the session cookie (requireProUser), so no bearer token is needed —
// same-origin credentials are sent automatically. Rendered only once the
// GitHub App is configured (see the dashboard gate).
import { useState } from "react";
import { useRouter } from "next/navigation";
import type { Severity } from "@/lib/types";

export interface SourceFinding {
  title: string;
  severity: Severity;
  consequence: string;
}

interface FixPr {
  repo: string;
  url: string;
  count: number;
}

export function GitHubPanel({ connected, findings }: { connected: boolean; findings: SourceFinding[] }) {
  const router = useRouter();
  const [busy, setBusy] = useState<"scan" | "disconnect" | "fix" | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [fixResult, setFixResult] = useState<{ prs: FixPr[] } | null>(null);

  async function post(path: string, kind: "scan" | "disconnect") {
    setError("");
    setNotice("");
    setBusy(kind);
    try {
      const res = await fetch(path, { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error ?? "Something went wrong. Try again.");
        setBusy(null);
        return;
      }
      if (kind === "scan") {
        setNotice("Source scan queued. Results will appear when the worker finishes.");
      } else {
        router.refresh();
      }
    } catch {
      setError("Couldn't reach the server. Try again.");
    }
    setBusy(null);
  }

  async function runFix() {
    setError("");
    setFixResult(null);
    setBusy("fix");
    try {
      const res = await fetch("/api/deep/github/fix", { method: "POST" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error ?? "Could not open fix PRs. Try again.");
        setBusy(null);
        return;
      }
      setFixResult({ prs: data.prs ?? [] });
    } catch {
      setError("Couldn't reach the server. Try again.");
    }
    setBusy(null);
  }

  return (
    <section style={{ marginTop: 40 }} aria-label="Source scanning — GitHub">
      <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
        Source · your repository
      </p>
      <div className="dxd-surface">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12, marginBottom: 12 }}>
          <h3 style={{ margin: 0, fontSize: 15 }}>GitHub source scan</h3>
          <span className={`dxd-chip ${connected ? "dxd-chip-verified" : ""}`} style={{ fontSize: 11 }}>
            {connected ? "connected" : "not connected"}
          </span>
        </div>

        <p style={{ margin: "0 0 14px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
          ShipLock reads repository contents and metadata to find committed secrets,
          vulnerable dependencies, and exposed tokens. Write access is used only after you
          click an explicit fix action: ShipLock creates a new review branch and pull request.
          It never writes your default branch, merges, or deploys.
        </p>

        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {!connected ? (
            <a href="/api/deep/github/connect" className="dxd-btn dxd-btn-paper" style={{ fontSize: 12, padding: "6px 14px" }}>
              Connect GitHub
            </a>
          ) : (
            <>
              <button
                type="button"
                className="dxd-btn dxd-btn-paper"
                onClick={() => post("/api/deep/github/scan", "scan")}
                disabled={busy !== null}
                style={{ fontSize: 12, padding: "6px 14px" }}
              >
                {busy === "scan" ? "Queueing…" : "Queue source scan"}
              </button>
              <button
                type="button"
                className="dxd-btn dxd-btn-paper"
                onClick={runFix}
                disabled={busy !== null}
                style={{ fontSize: 12, padding: "6px 14px" }}
              >
                {busy === "fix" ? "Opening PRs…" : "Open fix PRs"}
              </button>
              <button
                type="button"
                className="dxd-btn dxd-btn-ghost"
                onClick={() => post("/api/deep/github/disconnect", "disconnect")}
                disabled={busy !== null}
                style={{ fontSize: 12, padding: "6px 14px" }}
              >
                {busy === "disconnect" ? "Disconnecting…" : "Disconnect"}
              </button>
            </>
          )}
          {error && <span style={{ fontSize: 12, color: "var(--d-signal)", alignSelf: "center" }}>{error}</span>}
          {notice && <span style={{ fontSize: 12, color: "var(--d-muted)", alignSelf: "center" }}>{notice}</span>}
        </div>

        {fixResult && (
          <div style={{ marginTop: 12, fontSize: 12.5, lineHeight: 1.7 }}>
            {fixResult.prs.length > 0 ? (
              <>
                <p style={{ margin: "0 0 6px", color: "var(--d-muted)" }}>
                  Opened {fixResult.prs.length} pull request{fixResult.prs.length !== 1 ? "s" : ""} — review and merge:
                </p>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {fixResult.prs.map((pr) => (
                    <li key={pr.url}>
                      <a href={pr.url} target="_blank" rel="noopener noreferrer" style={{ color: "var(--d-bronze)" }}>
                        {pr.repo} — {pr.count} dependenc{pr.count !== 1 ? "ies" : "y"} bumped
                      </a>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <p style={{ margin: 0, color: "var(--d-muted)" }}>
                No auto-fixable dependencies found — nothing with a known patched version to bump.
              </p>
            )}
          </div>
        )}

        {connected && findings.length > 0 && (
          <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 10 }}>
            {findings.map((f, i) => (
              <div key={i} style={{ borderTop: "1px solid var(--d-line)", paddingTop: 10 }}>
                <div style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                  <span className={`dxd-chip ${f.severity === "CRITICAL" ? "dxd-chip-critical" : ""}`} style={{ fontSize: 10.5 }}>
                    {f.severity}
                  </span>
                  <span style={{ fontSize: 13, fontWeight: 600 }}>{f.title}</span>
                </div>
                <p style={{ margin: "6px 0 0", fontSize: 12, lineHeight: 1.6, color: "var(--d-muted)" }}>{f.consequence}</p>
              </div>
            ))}
          </div>
        )}

        {connected && findings.length === 0 && (
          <p style={{ marginTop: 14, marginBottom: 0, fontSize: 12, color: "var(--d-muted)" }}>
            No source findings. Run a scan after your next push to re-check.
          </p>
        )}
      </div>
    </section>
  );
}
