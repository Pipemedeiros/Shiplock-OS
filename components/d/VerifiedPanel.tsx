"use client";

// Owner control for the public "ShipLock Verified" report. Enable/disable
// sharing, copy the live report link + the embeddable badge snippet, preview.
// Same bearer-token pattern as ManageBillingButton. Token/link are only ever
// shown here to the paid owner.

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { buildBadgeSnippet, reportUrl } from "@/lib/verified/badge";

const preStyle = {
  margin: "8px 0 0", fontSize: 10.5, lineHeight: 1.5, maxHeight: 140, overflow: "auto" as const,
  background: "var(--d-porcelain)", border: "1px solid var(--d-line)", borderRadius: 8,
  padding: "10px 12px", userSelect: "all" as const, whiteSpace: "pre-wrap" as const, wordBreak: "break-all" as const,
};

export function VerifiedPanel({
  initialEnabled,
  initialToken,
  appUrl,
}: {
  initialEnabled: boolean;
  initialToken: string | null;
  appUrl: string;
}) {
  const [enabled, setEnabled] = useState(initialEnabled);
  const [token, setToken] = useState<string | null>(initialToken);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function call(action: "enable" | "disable" | "rotate") {
    setError("");
    setBusy(true);
    try {
      const supabase = getSupabaseBrowser();
      const { data: { session } } = await supabase.auth.getSession();
      const res = await fetch("/api/verified", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}),
        },
        body: JSON.stringify({ action }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Something went wrong. Try again.");
        return;
      }
      setEnabled(Boolean(data.enabled));
      if (data.token) setToken(data.token);
    } catch {
      setError("Couldn't reach the server. Try again in a moment.");
    } finally {
      setBusy(false);
    }
  }

  const link = enabled && token ? reportUrl(token, appUrl) : null;
  const badge = enabled && token ? buildBadgeSnippet(token, appUrl) : null;

  return (
    <div className="dxd-surface">
      <h3 style={{ margin: "0 0 10px", fontSize: 15 }}>Verified report</h3>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        A public, honestly-scoped security posture page you can share with your own investors and
        customers — proof your app is under continuous monitoring. It shows posture, scope, and
        cadence only, never your specific findings. Off until you turn it on.
      </p>

      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
        <button
          type="button"
          className={enabled ? "dxd-btn dxd-btn-ghost" : "dxd-btn"}
          onClick={() => call(enabled ? "disable" : "enable")}
          disabled={busy}
          style={{ fontSize: 12, padding: "6px 12px" }}
        >
          {busy ? "…" : enabled ? "Disable sharing" : "Enable & get link"}
        </button>
        {enabled && (
          <button type="button" className="dxd-btn dxd-btn-ghost" onClick={() => call("rotate")} disabled={busy} style={{ fontSize: 12, padding: "6px 12px" }}>
            Rotate link
          </button>
        )}
        <span className="dxd-mono" style={{ fontSize: 11, color: enabled ? "#4ade80" : "var(--d-muted-light)" }}>
          {enabled ? "● Public" : "○ Private"}
        </span>
      </div>

      {error && <p style={{ fontSize: 12, color: "var(--d-signal)", marginTop: 10 }}>{error}</p>}

      {link && (
        <>
          <div style={{ marginTop: 14 }}>
            <div className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)" }}>Live report link</div>
            <pre className="dxd-mono" style={preStyle}>{link}</pre>
            <a href={link} target="_blank" rel="noopener noreferrer" className="dxd-mono" style={{ fontSize: 12 }}>
              Preview →
            </a>
          </div>
          <div style={{ marginTop: 14 }}>
            <div className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)" }}>Embed badge (paste on your site)</div>
            <pre className="dxd-mono" style={preStyle}>{badge}</pre>
          </div>
        </>
      )}
    </div>
  );
}
