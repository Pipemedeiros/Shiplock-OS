"use client";

// Connect the customer's own coding agent to ShipLock over MCP. The agent can
// read findings and approved AI checks, and send back answers ShipLock then
// verifies. The token is shown once; the list shows names only. ShipLock
// cannot start the agent: checks are picked up when the customer runs it.

import { useEffect, useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

export interface TokenMeta { id: string; name: string; created_at: string; last_used_at: string | null }
type Host = "claude-code" | "codex" | "chatgpt" | "api";

export function setupCommand(host: "claude-code" | "codex", token: string): string {
  if (host === "claude-code") return `claude mcp add shiplock --env SHIPLOCK_TOKEN=${token} -- npx -y @shiplock/mcp`;
  return `[mcp_servers.shiplock]\ncommand = "npx"\nargs = ["-y", "@shiplock/mcp"]\nenv = { SHIPLOCK_TOKEN = "${token}" }`;
}

const pre = { margin: "6px 0 0", fontSize: 12, lineHeight: 1.5, overflow: "auto" as const, whiteSpace: "pre" as const,
  background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 6, padding: "10px 12px", userSelect: "all" as const };
const note = { fontSize: 13, color: "var(--muted)", margin: "0 0 10px", maxWidth: 700 } as const;

export function AgentSetupView({ host, tokens, fresh, busy, error, onGenerate, onRevoke }: {
  host: Host; tokens: TokenMeta[]; fresh: string | null; busy: boolean; error: string;
  onGenerate: () => void; onRevoke: (id: string) => void;
}) {
  if (host === "api") return null;
  if (host === "chatgpt") {
    return <p style={note}>ChatGPT connection is not available yet. Choose Claude Code or Codex to connect an agent today.</p>;
  }
  const where = host === "claude-code" ? "Run this in your terminal:" : "Add this to ~/.codex/config.toml:";
  return (
    <div style={{ marginBottom: 12 }}>
      <p style={note}>
        Connect your agent so it can read your findings and pick up approved checks when you run it. ShipLock
        cannot start your agent. Your agent sends back findings and suggested fixes; ShipLock checks each one
        against GitHub, every pull request still needs your click, and ShipLock never merges.
      </p>
      <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onGenerate} disabled={busy}>
        {busy ? "Creating…" : "Create a token"}
      </button>
      {error ? <p style={{ ...note, color: "var(--crit)", marginTop: 6 }}>{error}</p> : null}
      {fresh ? (
        <div style={{ marginTop: 10 }}>
          <p style={{ ...note, color: "var(--ink)" }}>Copy it now: this token is shown only once. {where}</p>
          <pre style={pre}>{setupCommand(host, fresh)}</pre>
        </div>
      ) : null}
      {tokens.length > 0 ? (
        <div style={{ marginTop: 10 }}>
          {tokens.map((t) => (
            <div key={t.id} className="v3-between" style={{ fontSize: 13, padding: "3px 0" }}>
              <span>{t.name}, created {new Date(t.created_at).toLocaleDateString("en-US")}{t.last_used_at ? `, last used ${new Date(t.last_used_at).toLocaleDateString("en-US")}` : ""}</span>
              <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={() => onRevoke(t.id)} disabled={busy}>Revoke</button>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

async function authHeader(): Promise<Record<string, string>> {
  const { data: { session } } = await getSupabaseBrowser().auth.getSession();
  return session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {};
}

export function AgentSetup({ host }: { host: Host }) {
  const [tokens, setTokens] = useState<TokenMeta[]>([]);
  const [fresh, setFresh] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    try {
      const res = await fetch("/api/tokens", { headers: await authHeader() });
      if (res.ok) setTokens(((await res.json()) as { tokens?: TokenMeta[] }).tokens ?? []);
    } catch { /* the list is a convenience; creating still works */ }
  }
  useEffect(() => { void load(); }, []);

  async function generate() {
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/tokens", { method: "POST",
        headers: { "content-type": "application/json", ...(await authHeader()) }, body: JSON.stringify({ name: "MCP token" }) });
      const data = (await res.json().catch(() => ({}))) as { token?: string; error?: string };
      if (!res.ok || !data.token) { setError(data.error ?? "Could not create a token. Try again."); return; }
      setFresh(data.token);
      await load();
    } catch { setError("Could not reach ShipLock. Try again."); }
    finally { setBusy(false); }
  }

  async function revoke(id: string) {
    setBusy(true);
    try { await fetch(`/api/tokens?id=${encodeURIComponent(id)}`, { method: "DELETE", headers: await authHeader() }); await load(); }
    finally { setBusy(false); }
  }

  return <AgentSetupView host={host} tokens={tokens} fresh={fresh} busy={busy} error={error} onGenerate={generate} onRevoke={revoke} />;
}
