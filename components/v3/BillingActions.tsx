"use client";

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

/** Manage or cancel a subscription through Stripe's own portal. */
export function BillingActions() {
  const [busy, setBusy] = useState<"manage" | "cancel" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function open(intent: "manage" | "cancel") {
    setBusy(intent);
    setError(null);
    try {
      const { data: { session } } = await getSupabaseBrowser().auth.getSession();
      const res = await fetch("/api/portal", {
        method: "POST",
        headers: { "content-type": "application/json", ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}) },
        body: JSON.stringify({ intent }),
      });
      const body = (await res.json().catch(() => ({}))) as { url?: string; error?: string };
      if (!res.ok || !body.url) throw new Error(body.error ?? "The billing page could not be opened. Try again.");
      window.location.assign(body.url);
    } catch (e) {
      setError(e instanceof Error ? e.message : "The billing page could not be opened. Try again.");
      setBusy(null);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-start" }}>
      <div className="v3-row" style={{ gap: 8 }}>
        <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy !== null} onClick={() => open("manage")}>
          {busy === "manage" ? "Opening…" : "Manage billing"}
        </button>
        <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy !== null} onClick={() => open("cancel")}>
          {busy === "cancel" ? "Opening…" : "Cancel subscription"}
        </button>
      </div>
      {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
    </div>
  );
}
