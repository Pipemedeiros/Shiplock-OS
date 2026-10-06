"use client";

import Link from "next/link";
import { useState } from "react";
import { agentFixPrompt } from "@/lib/agentHandoff";
import type { FixKind } from "@/lib/agent/findings";

/** One finding handed to the customer's own agent over ShipLock's MCP tools
 * (Felipe 2026-10-06). The agent proposes; the person reviews and merges. */
export function AgentHandoff({ finding }: { finding: { id: string; title: string; repository: string | null; fixKind: FixKind } }) {
  const prompt = agentFixPrompt(finding);
  const [copied, setCopied] = useState<"yes" | "no" | null>(null);
  return (
    <div>
      <b style={{ fontWeight: 500 }}>Hand it to your agent</b>
      <p className="v3-small" style={{ marginTop: 4 }}>
        Paste this into Claude Code or Codex with ShipLock connected (<Link href="/dashboard/settings">set up</Link>).
      </p>
      <pre className="v3-trace" style={{ marginTop: 8, whiteSpace: "pre-wrap", overflowWrap: "anywhere", fontSize: 12.5 }}>{prompt}</pre>
      <div className="v3-row" style={{ gap: 10, marginTop: 8 }}>
        <button className="v3-btn v3-btn-sm v3-ghost" onClick={async () => {
          try { await navigator.clipboard.writeText(prompt); setCopied("yes"); } catch { setCopied("no"); }
        }}>Copy instruction</button>
        <span role="status" className="v3-small">
          {copied === "yes" ? "Copied." : copied === "no" ? "Copy failed. Select the text above instead." : ""}
        </span>
      </div>
    </div>
  );
}
