"use client";

// Read-only Supabase Management connection. This is what lets us read your
// actual RLS policies rather than only inferring that RLS is missing — the
// difference between "this table is unprotected" and "this table has a policy
// that lets every logged-in user read every row", which is the more common and
// more dangerous failure.

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { SupabaseRepositoryAssociations } from "./SupabaseRepositoryAssociations";

export function SupabasePanel({
  connected,
  projectRef,
  configured,
}: {
  connected: boolean;
  projectRef: string | null;
  configured: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [associationBusy, setAssociationBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [isConnected, setIsConnected] = useState(connected);

  async function post(path: string) {
    setBusy(true);
    setMessage("");
    try {
      const supabase = getSupabaseBrowser();
      const { data: { session } } = await supabase.auth.getSession();
      const res = await fetch(path, {
        method: "POST",
        headers: session?.access_token
          ? { Authorization: `Bearer ${session.access_token}` }
          : {},
      });
      const data = await res.json();
      if (!res.ok) {
        setMessage(data.error ?? "That didn't work. Try again.");
        return;
      }
      if (path.endsWith("/disconnect")) {
        setIsConnected(false);
        setMessage("Disconnected. Policy checks have stopped.");
      } else {
        // Reads run in the background queue (3F-C2c-5); results land on Risks.
        setMessage("Policy check queued. Results appear on your Risks tab in a few minutes.");
      }
    } catch {
      setMessage("Couldn't reach the server.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h3 style={{ margin: "0 0 10px", fontSize: 15 }}>Supabase, policy access</h3>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--muted)" }}>
        Your anon key shows us whether a table is protected. It can&apos;t show us whether the
        protection is <em>correct</em>. A policy that lets every signed-in user read every row
        looks identical from outside. Connecting read-only access lets us check the policies
        themselves.
      </p>
      <p style={{ margin: "0 0 14px", fontSize: 12.5, lineHeight: 1.7, color: "var(--muted)" }}>
        <b>We only ever read.</b> ShipLock never writes to your production database. Database
        and access-control fixes always arrive as a migration pull request you review and merge.
        You can disconnect at any time, which deletes the token.
      </p>

      {!configured ? (
        <p className="v3-mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
          Management API connection is not available yet.
        </p>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {isConnected ? (
            <>
              <button
                type="button"
                className="v3-btn v3-btn-sm v3-primary"
                onClick={() => post("/api/deep/supabase/scan")}
                disabled={busy || associationBusy}
              >
                {busy ? "…" : "Check policies now"}
              </button>
              <button
                type="button"
                className="v3-btn v3-btn-sm v3-ghost"
                onClick={() => post("/api/deep/supabase/disconnect")}
                disabled={busy || associationBusy}
              >
                Disconnect
              </button>
              <span className="v3-mono" style={{ fontSize: 11, color: "var(--ok)" }}>
                ● Connected{projectRef ? ` · ${projectRef}` : ""}
              </span>
            </>
          ) : (
            <>
              {associationBusy ? (
                <button type="button" className="v3-btn v3-btn-sm v3-primary" disabled>
                  Connect read-only access
                </button>
              ) : (
                <a
                  href="/api/deep/supabase/connect"
                  className="v3-btn v3-btn-sm v3-primary"
                >
                  Connect read-only access
                </a>
              )}
              <span className="v3-mono" style={{ fontSize: 11, color: "var(--muted)" }}>
                ○ Not connected
              </span>
            </>
          )}
        </div>
      )}

      {message && (
        <p style={{ fontSize: 12, color: "var(--muted)", marginTop: 10 }}>{message}</p>
      )}
      <SupabaseRepositoryAssociations disabled={busy} onMutationBusyChange={setAssociationBusy} />
    </div>
  );
}
