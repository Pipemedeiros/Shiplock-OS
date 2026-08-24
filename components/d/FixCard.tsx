"use client";

// One finding → one fix, with an editable preview and a button that applies it
// the safe way for its category: a reviewable PR (migration / code / draft) or a
// deep-link (Supabase dashboard / secret rotation). Nothing here writes prod.

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { fixLane, type FixableFinding } from "@/lib/fixes/lane";
import { buildMigrationFix, buildCodeFix, buildDeepLink } from "@/lib/fixes/content";
import { AgreementStrip } from "@/components/d/CoverageBoard";
import { correlationLayers } from "@/lib/graph/layerLabels";

const sevColor: Record<string, string> = {
  CRITICAL: "var(--d-signal, #ef4444)", WARNING: "var(--d-bronze, #d97706)", INFO: "var(--d-muted, #64748b)",
};

export function FixCard({ finding, projectRef }: { finding: FixableFinding; projectRef?: string | null }) {
  const lane = fixLane(finding);
  const seed = lane.method === "migration-pr"
    ? buildMigrationFix(finding).content
    : lane.method === "code-pr" || lane.method === "draft-pr"
      ? buildCodeFix(finding).content
      : "";

  const [content, setContent] = useState(seed);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [prUrl, setPrUrl] = useState<string | null>(null);

  async function openPr() {
    setError(""); setBusy(true);
    try {
      const supabase = getSupabaseBrowser();
      const { data: { session } } = await supabase.auth.getSession();
      const res = await fetch("/api/deep/fix", {
        method: "POST",
        headers: { "content-type": "application/json", ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}) },
        body: JSON.stringify({ finding, editedContent: content }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? "Couldn't open the PR."); return; }
      setPrUrl(data.url ?? null);
    } catch {
      setError("Couldn't reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const deepLink =
    lane.method === "deep-link" ? buildDeepLink(finding, projectRef, lane.external) : null;

  return (
    <div className="dxd-surface" style={{ padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "baseline" }}>
        <h4 style={{ margin: 0, fontSize: 14 }}>{finding.title}</h4>
        <span className="dxd-mono" style={{ fontSize: 10, color: sevColor[finding.severity] }}>{finding.severity}</span>
      </div>

      {/* Which layers independently confirmed this. Renders only where 2+ agree
          (AgreementStrip returns null otherwise), so its presence is the signal
          and its absence never implies a finding is weak. */}
      {finding.correlation && (
        <div style={{ marginTop: 12 }}>
          <AgreementStrip
            layers={correlationLayers(finding.correlation.surfaces)}
            proven={finding.correlation.proven}
          />
        </div>
      )}

      {lane.method === "deep-link" ? (
        <div style={{ marginTop: 10 }}>
          <p style={{ fontSize: 12.5, color: "var(--d-muted)", margin: "0 0 10px" }}>{finding.fix}</p>
          {/* No button when there is nowhere honest to send them: a DNS record is
              edited wherever their DNS lives, and a third-party key is rotated in
              that vendor's console. A confident link to the wrong page is worse
              than no link — it lets someone believe they've done the fix. */}
          {deepLink ? (
            <a
              href={deepLink}
              target="_blank"
              rel="noopener noreferrer"
              className="dxd-btn dxd-btn-paper"
              style={{ fontSize: 12, padding: "6px 12px", textDecoration: "none" }}
            >
              {lane.label} →
            </a>
          ) : null}
        </div>
      ) : (
        <div style={{ marginTop: 10 }}>
          <div className="dxd-mono" style={{ fontSize: 10, color: "var(--d-muted)", marginBottom: 4 }}>
            {lane.method === "migration-pr" ? "Migration (review & edit, then open a PR you merge)" : "Fix request (edit if needed, then open a PR)"}
          </div>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            spellCheck={false}
            rows={Math.min(12, Math.max(4, content.split("\n").length + 1))}
            className="dxd-mono"
            style={{ width: "100%", fontSize: 11, lineHeight: 1.5, padding: "10px 12px", background: "var(--d-porcelain)", border: "1px solid var(--d-line)", borderRadius: 8, resize: "vertical" }}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 8 }}>
            <button type="button" className="dxd-btn dxd-btn-paper" onClick={openPr} disabled={busy || !content.trim()} style={{ fontSize: 12, padding: "6px 12px" }}>
              {busy ? "Opening PR…" : lane.label}
            </button>
            {prUrl && (
              <a href={prUrl} target="_blank" rel="noopener noreferrer" className="dxd-mono" style={{ fontSize: 12 }}>
                View PR →
              </a>
            )}
          </div>
        </div>
      )}

      {error && <p style={{ fontSize: 12, color: "var(--d-signal)", marginTop: 8 }}>{error}</p>}
    </div>
  );
}
