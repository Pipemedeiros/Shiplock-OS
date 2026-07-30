"use client";

// Real checkout entry point — no caller of POST /api/checkout existed
// anywhere in the app before this. The route itself verifies the bearer
// token, derives billing email server-side, and returns a Stripe Checkout URL.
//
// `plan` selects the term (see lib/plans.ts). Omitted, it stays the monthly
// subscription, which is what every existing call site wants.

import { useState } from "react";
import { Loader2 } from "lucide-react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { track } from "@/lib/analytics";
import type { PlanId } from "@/lib/plans";

export function UpgradeButton({
  summary,
  plan = "monthly",
  label,
  variant = "primary",
  note,
}: {
  summary?: string;
  plan?: PlanId;
  label?: string;
  variant?: "primary" | "ghost";
  note?: string;
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleUpgrade() {
    track("checkout_started", { from_scan: Boolean(summary), plan });
    setError("");
    setLoading(true);
    try {
      const supabase = getSupabaseBrowser();
      const {
        data: { session },
      } = await supabase.auth.getSession();

      const res = await fetch("/api/checkout", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(session?.access_token
            ? { Authorization: `Bearer ${session.access_token}` }
            : {}),
        },
        body: JSON.stringify({ summary, plan }),
      });
      const data = await res.json();
      if (!res.ok || !data.url) {
        setError(data.error ?? "Checkout failed. Try again.");
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
    <div>
      <button
        type="button"
        className={variant === "ghost" ? "dxd-btn dxd-btn-ghost" : "dxd-btn"}
        onClick={handleUpgrade}
        disabled={loading}
      >
        {loading ? <Loader2 className="size-4 animate-spin" /> : label ?? "Put us on retainer — $49/mo"}
      </button>
      <p style={{ fontSize: 12, color: "var(--d-muted)", marginTop: 10, lineHeight: 1.6 }}>
        {note ??
          "7 days free — no charge today. Cancel anytime in one click. Secure checkout by Stripe; we never see your card."}
      </p>
      {error && (
        <p style={{ fontSize: 13, color: "var(--d-signal)", marginTop: 8 }}>{error}</p>
      )}
    </div>
  );
}
