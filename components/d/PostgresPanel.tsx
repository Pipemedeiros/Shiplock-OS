"use client";

// Direct Postgres connection, for the database half of ShipLock on stacks we
// don't host: Neon, Railway, Render, RDS, Fly, self-hosted.
//
// This is not a third connection — it is the same "your database" slot the
// Supabase panel fills, shown to customers who aren't on Supabase. The dashboard
// renders one or the other, never both.
//
// Two things this copy has to do honestly, because the alternative is a customer
// trusting a thinner scan than they think they have:
//  1. ask for a READ-ONLY role and explain why, rather than asking for whatever
//     DSN their provider showed them
//  2. say plainly which checks this path cannot run — a shorter findings list
//     must never be mistakable for a cleaner one

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

const SETUP_SQL = `create role shiplock_reader login password '<a strong password>';
grant connect on database <your_db> to shiplock_reader;
grant usage on schema public to shiplock_reader;
grant select on all tables in schema public to shiplock_reader;`;

export function PostgresPanel({
  connected,
  display,
}: {
  connected: boolean;
  display: string | null;
}) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(false);
  const [isConnected, setIsConnected] = useState(connected);
  const [shown, setShown] = useState(display);
  const [dsn, setDsn] = useState("");
  const [showForm, setShowForm] = useState(false);

  async function post(body: Record<string, unknown>) {
    setBusy(true);
    setMessage("");
    setError(false);
    try {
      const supabase = getSupabaseBrowser();
      const {
        data: { session },
      } = await supabase.auth.getSession();
      const res = await fetch("/api/deep/postgres", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {}),
        },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(true);
        setMessage(data.error ?? "That didn't work. Try again.");
        return;
      }

      if (body.action === "disconnect") {
        setIsConnected(false);
        setShown(null);
        setMessage("Disconnected. We've forgotten the credentials and stopped policy checks.");
        return;
      }

      if (body.action === "connect") {
        setIsConnected(true);
        setShown(data.display ?? null);
        // Clear the credential from component state the moment it is no longer
        // needed — it should not sit in memory behind a re-render.
        setDsn("");
        setShowForm(false);
      }

      setMessage(
        data.findings === 0
          ? "Read your policies. Nothing permissive found."
          : `Read your policies. ${data.findings} issue${data.findings === 1 ? "" : "s"} on your Risks tab.`
      );
    } catch {
      setError(true);
      setMessage("Couldn't reach the server.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="dxd-surface">
      <h3 style={{ margin: "0 0 10px", fontSize: 15 }}>Your database, policy access</h3>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        Any Postgres works: Neon, Railway, Render, RDS, Fly, your own hardware. We read your Row
        Level Security policies so we can tell you whether the protection is <em>correct</em>, not
        just whether it exists. A policy that lets every signed-in user read every row looks
        identical from outside.
      </p>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        <b>Give us a read-only role, and we&apos;ll check that you did.</b>{" "}
        We refuse the
        connection if the role can write, or if it can bypass Row Level Security, so
        &ldquo;ShipLock cannot change your database&rdquo; is something your grants enforce, not
        something you have to take our word for.
      </p>

      {isConnected ? (
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button
            type="button"
            className="dxd-btn"
            onClick={() => post({ action: "scan" })}
            disabled={busy}
            style={{ fontSize: 12, padding: "6px 12px" }}
          >
            {busy ? "…" : "Check policies now"}
          </button>
          <button
            type="button"
            className="dxd-btn dxd-btn-ghost"
            onClick={() => post({ action: "disconnect" })}
            disabled={busy}
            style={{ fontSize: 12, padding: "6px 12px" }}
          >
            Disconnect
          </button>
          <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-verified)" }}>
            ● Connected{shown ? ` · ${shown}` : ""}
          </span>
        </div>
      ) : showForm ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void post({ action: "connect", connectionString: dsn });
          }}
        >
          <p style={{ margin: "0 0 8px", fontSize: 12, color: "var(--d-muted)" }}>
            Create the role, then paste its connection string:
          </p>
          <pre
            className="dxd-mono"
            style={{
              fontSize: 11,
              lineHeight: 1.7,
              padding: 10,
              overflowX: "auto",
              background: "var(--d-surface-2, rgba(0,0,0,0.15))",
              borderRadius: 6,
              margin: "0 0 10px",
            }}
          >
            {SETUP_SQL}
          </pre>
          <input
            type="password"
            value={dsn}
            onChange={(e) => setDsn(e.target.value)}
            placeholder="postgresql://shiplock_reader:…@host:5432/dbname"
            autoComplete="off"
            spellCheck={false}
            required
            className="dxd-mono"
            style={{
              width: "100%",
              fontSize: 12,
              padding: "8px 10px",
              borderRadius: 6,
              border: "1px solid var(--d-border, rgba(255,255,255,0.15))",
              background: "transparent",
              color: "inherit",
              marginBottom: 10,
            }}
          />
          <div style={{ display: "flex", gap: 8 }}>
            <button
              type="submit"
              className="dxd-btn"
              disabled={busy || dsn.length === 0}
              style={{ fontSize: 12, padding: "6px 12px" }}
            >
              {busy ? "Checking…" : "Connect"}
            </button>
            <button
              type="button"
              className="dxd-btn dxd-btn-ghost"
              onClick={() => {
                setDsn("");
                setShowForm(false);
              }}
              disabled={busy}
              style={{ fontSize: 12, padding: "6px 12px" }}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <button
            type="button"
            className="dxd-btn"
            onClick={() => setShowForm(true)}
            style={{ fontSize: 12, padding: "6px 12px" }}
          >
            Connect read-only access
          </button>
          <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted-light)" }}>
            ○ Not connected
          </span>
        </div>
      )}

      {message && (
        <p
          style={{
            fontSize: 12,
            color: error ? "var(--d-critical, #e5484d)" : "var(--d-muted)",
            marginTop: 10,
            lineHeight: 1.6,
          }}
        >
          {message}
        </p>
      )}
    </div>
  );
}
