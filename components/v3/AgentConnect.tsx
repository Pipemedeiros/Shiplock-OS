"use client";

import { useState } from "react";
import { codexHttpConfig, httpCommand } from "@/components/d/AgentSetup";
import { MCP_TOOLS } from "@/lib/mcpTools";

/** The landing's connect card: the same commands Settings shows, with the
 * token left as an environment variable the reader creates after signing in. */
const ORIGIN = "https://shiplock.dev";
const HOSTS = {
  "Claude Code": { where: "Terminal", body: httpCommand(ORIGIN, "$SHIPLOCK_TOKEN") },
  Codex: { where: "~/.codex/config.toml", body: codexHttpConfig(ORIGIN) },
} as const;
type Host = keyof typeof HOSTS;

export function AgentConnect() {
  const [host, setHost] = useState<Host>("Claude Code");
  const [copied, setCopied] = useState<"yes" | "no" | null>(null);
  const { where, body } = HOSTS[host];
  return (
    <div className="v3-connect">
      <div className="v3-connect-tabs" role="tablist" aria-label="Agent">
        {(Object.keys(HOSTS) as Host[]).map((h) => (
          <button key={h} role="tab" type="button" aria-selected={h === host}
            className={h === host ? "on" : ""} onClick={() => { setHost(h); setCopied(null); }}>{h}</button>
        ))}
        <span className="v3-connect-where v3-mono">{where}</span>
      </div>
      <pre className="v3-connect-code v3-mono" role="tabpanel">{body}</pre>
      <div className="v3-between v3-connect-foot">
        <span role="status" className="v3-mono">
          {copied === "yes" ? "Copied" : copied === "no" ? "Select the text instead" : "Token from Settings after sign in"}
        </span>
        <button type="button" className="v3-btn v3-btn-sm v3-ondark" onClick={async () => {
          try { await navigator.clipboard.writeText(body); setCopied("yes"); } catch { setCopied("no"); }
        }}>Copy</button>
      </div>
      <ul className="v3-tools v3-mono" aria-label="ShipLock MCP tools">
        {MCP_TOOLS.map((t) => <li key={t.name}>{t.name}</li>)}
      </ul>
    </div>
  );
}
