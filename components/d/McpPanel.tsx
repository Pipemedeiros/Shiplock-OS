"use client";

// "Connect your coding agent" — generate a ShipLock token and get the MCP config
// for Claude Code / Cursor / Codex. The token is shown ONCE on creation. Existing
// tokens are listed by metadata only (never the value) and can be revoked.

import { useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

export interface TokenMeta {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

const preStyle = {
  margin: "6px 0 0", fontSize: 10.5, lineHeight: 1.5, maxHeight: 200, overflow: "auto" as const,
  background: "var(--d-porcelain)", border: "1px solid var(--d-line)", borderRadius: 8,
  padding: "10px 12px", userSelect: "all" as const, whiteSpace: "pre" as const,
};

function configJson(token: string): string {
  return JSON.stringify(
    { mcpServers: { shiplock: { command: "npx", args: ["-y", "@shiplock/mcp"], env: { SHIPLOCK_TOKEN: token } } } },
    null, 2
  );
}

async function authHeader(): Promise<Record<string, string>> {
  const { data: { session } } = await getSupabaseBrowser().auth.getSession();
  return session?.access_token ? { Authorization: `Bearer ${session.access_token}` } : {};
}

export function McpPanel({ initialTokens = [] }: { initialTokens?: TokenMeta[] }) {
  const [tokens, setTokens] = useState<TokenMeta[]>(initialTokens);
  const [fresh, setFresh] = useState<string | null>(null); // the just-created raw token
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    try {
      const res = await fetch("/api/tokens", { headers: await authHeader() });
      const data = await res.json();
      if (res.ok) setTokens(data.tokens ?? []);
    } catch { /* non-critical */ }
  }

  async function generate() {
    setError(""); setBusy(true);
    try {
      const res = await fetch("/api/tokens", { method: "POST", headers: { "content-type": "application/json", ...(await authHeader()) }, body: JSON.stringify({ name: "MCP token" }) });
      const data = await res.json();
      if (!res.ok) { setError(data.error ?? "Couldn't create a token."); return; }
      setFresh(data.token);
      await load();
    } catch { setError("Couldn't reach the server."); }
    finally { setBusy(false); }
  }

  async function revoke(id: string) {
    await fetch(`/api/tokens?id=${encodeURIComponent(id)}`, { method: "DELETE", headers: await authHeader() });
    await load();
  }

  return (
    <div className="dxd-surface">
      <h3 style={{ margin: "0 0 10px", fontSize: 15 }}>Connect your coding agent</h3>
      <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        Add ShipLock to Claude Code, Cursor, or Codex over MCP. Your agent pulls your open security
        findings into context and applies the fixes — each one a diff you review, never a silent change.
      </p>

      <button type="button" className="dxd-btn dxd-btn-paper" onClick={generate} disabled={busy} style={{ fontSize: 12, padding: "6px 12px" }}>
        {busy ? "Generating…" : "Generate token"}
      </button>
      {error && <p style={{ fontSize: 12, color: "var(--d-signal)", marginTop: 8 }}>{error}</p>}

      {fresh && (
        <div style={{ marginTop: 14 }}>
          <div className="dxd-mono" style={{ fontSize: 11, color: "var(--d-bronze)" }}>
            Copy this token now — it&apos;s shown only once.
          </div>
          <pre className="dxd-mono" style={preStyle}>{fresh}</pre>
          <div className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)", marginTop: 10 }}>
            Claude Code / Cursor — save as <code>.mcp.json</code> (or <code>.cursor/mcp.json</code>):
          </div>
          <pre className="dxd-mono" style={preStyle}>{configJson(fresh)}</pre>
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--d-bronze)" }}>Codex (~/.codex/config.toml)</summary>
            <pre className="dxd-mono" style={preStyle}>{`[mcp_servers.shiplock]\ncommand = "npx"\nargs = ["-y", "@shiplock/mcp"]\nenv = { SHIPLOCK_TOKEN = "${fresh}" }`}</pre>
          </details>
        </div>
      )}

      {tokens.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)", marginBottom: 6 }}>Active tokens</div>
          {tokens.map((t) => (
            <div key={t.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, fontSize: 12, padding: "4px 0" }}>
              <span className="dxd-mono">{t.name} · created {new Date(t.created_at).toLocaleDateString()}{t.last_used_at ? ` · used ${new Date(t.last_used_at).toLocaleDateString()}` : ""}</span>
              <button type="button" className="dxd-btn dxd-btn-ghost" onClick={() => revoke(t.id)} style={{ fontSize: 11, padding: "3px 8px" }}>Revoke</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
