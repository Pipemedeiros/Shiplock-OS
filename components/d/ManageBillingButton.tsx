"use client";

// Entry point for POST /api/portal (Stripe billing portal) — same
// bearer-token pattern as UpgradeButton. Rendered only for users with an
// active or past subscription; the route 402s cleanly for anyone else.

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

export function ManageBillingButton() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleOpen() {
    setError("");
    setLoading(true);
    try {
      const supabase = getSupabaseBrowser();
      const {
        data: { session },
      } = await supabase.auth.getSession();

      const res = await fetch("/api/portal", {
        method: "POST",
        headers: session?.access_token
          ? { Authorization: `Bearer ${session.access_token}` }
          : {},
      });
      const data = await res.json();
      if (!res.ok || !data.url) {
        setError(data.error ?? "Couldn't open billing. Try again.");
        setLoading(false);
        return;
      }
      window.location.href = data.url;
    } catch {
      setError("Couldn't reach the server. Try again in a moment.");
      setLoading(false);
    }
  }

  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <button
        type="button"
        className="dxd-btn dxd-btn-ghost"
        onClick={handleOpen}
        disabled={loading}
        style={{ fontSize: 12, padding: "6px 12px" }}
      >
        {loading ? "Opening…" : "Billing"}
      </button>
      {error && <span style={{ fontSize: 12, color: "var(--d-signal)" }}>{error}</span>}
    </span>
  );
}
