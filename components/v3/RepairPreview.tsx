"use client";

import { useState } from "react";
import type { RepairPreview } from "@/lib/fixes/preview";

// One preview before every fix click: the exact files the
// pull request would add or change, where it goes, and that tests were not
// run. "Open pull request" here is the only way to send the click.
const pre = { margin: "4px 0 8px", fontSize: 11.5, lineHeight: 1.45, maxHeight: 220, overflow: "auto" as const,
  whiteSpace: "pre" as const, background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 6, padding: "8px 10px" };

const UNAVAILABLE: Record<string, string> = {
  no_changes: "There is nothing to change right now, so there is no pull request to open.",
  not_fixable: "This one needs a decision from you, so there is no pull request to open.",
  finding_unavailable: "This is no longer open, so there is nothing to fix.",
  repository_unavailable: "ShipLock can no longer reach that repository. Reselect it and try again.",
  source_changed: "The code changed since this was proposed, so the change no longer applies.",
  fork_pull_request: "This pull request comes from a fork, so ShipLock cannot push to its branch.",
  pull_request_closed: "That pull request branch is gone, so there is nothing to fix before merge.",
};

export function RepairPreviewView({ preview, busy, onOpen }: { preview: RepairPreview; busy: boolean; onOpen: () => void }) {
  if (preview.status === "already_open") {
    return <p className="v3-small">A pull request for this is already open. <a href={preview.url} target="_blank" rel="noreferrer">Review it on GitHub</a>.</p>;
  }
  if (preview.status === "unavailable") {
    return <p className="v3-small">{UNAVAILABLE[preview.code] ?? "There is no pull request to open for this right now."}</p>;
  }
  return (
    <div style={{ marginTop: 8 }}>
      <p className="v3-small" style={{ margin: 0 }}><strong>{preview.title}</strong></p>
      <p className="v3-small" style={{ margin: "2px 0 6px" }}>
        {preview.lane} for {preview.repository}, on a new branch {preview.branch} into {preview.base}. ShipLock never merges.
      </p>
      {preview.files.map((file) => (
        <div key={file.path}>
          <p className="v3-small" style={{ margin: 0 }}>{file.change === "add" ? "Adds" : "Changes"} {file.path}</p>
          {file.nameSetAtClick ? <p className="v3-small" style={{ margin: 0 }}>The date in the file name is set when you open the pull request.</p> : null}
          {file.before !== null ? (
            <details><summary className="v3-small">Current version</summary><pre style={pre}>{file.before}</pre></details>
          ) : null}
          <pre style={pre}>{file.after}</pre>
        </div>
      ))}
      <p className="v3-small">Tests were not run by ShipLock. Let your CI run and review the diff before merging.</p>
      <button type="button" className="v3-btn v3-btn-sm v3-primary" onClick={onOpen} disabled={busy}>
        {busy ? "Opening…" : "Open pull request"}
      </button>
    </div>
  );
}

/** Loads the preview for one button, then hands the confirmed click back. */
export function RepairPreviewPanel({ body, busy, onOpen }: { body: Record<string, unknown>; busy: boolean; onOpen: () => void }) {
  const [preview, setPreview] = useState<RepairPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function load() {
    setLoading(true); setError(null);
    try {
      const res = await fetch("/api/fix/preview", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const json = await res.json().catch(() => ({})) as RepairPreview & { error?: string };
      if (!res.ok) setError(json.error ?? "Could not build the preview. Try again.");
      else setPreview(json);
    } catch {
      setError("Could not reach ShipLock. Try again.");
    } finally {
      setLoading(false);
    }
  }

  if (preview) return <RepairPreviewView preview={preview} busy={busy} onOpen={onOpen} />;
  return (
    <span>
      <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={load} disabled={loading}>
        {loading ? "Preparing preview…" : "Preview the pull request"}
      </button>
      {error ? <span role="alert" className="v3-small" style={{ marginLeft: 8 }}>{error}</span> : null}
    </span>
  );
}
