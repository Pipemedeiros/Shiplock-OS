"use client";

// Dumb rendering only — all data-shaping and paywall filtering happens
// server-side in lib/agentBrief.ts / app/(d)/dashboard/page.tsx, which only
// passes this component a string when isPaid && latest. No fetch, no auth
// surface here.

import { useState } from "react";

export function AgentBrief({ markdown }: { markdown: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API can fail (permissions, insecure context) — the
      // textarea is still selectable/copyable manually, so no error UI needed.
    }
  }

  function handleDownload() {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "SECURITY.md";
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
        <button type="button" className="dxd-btn dxd-btn-ghost dxd-btn-sm" onClick={handleCopy}>
          {copied ? "Copied" : "Copy for your agent"}
        </button>
        <button type="button" className="dxd-btn dxd-btn-ghost dxd-btn-sm" onClick={handleDownload}>
          Download SECURITY.md
        </button>
      </div>
      <pre className="dxd-code" style={{ maxHeight: 360, overflow: "auto", whiteSpace: "pre-wrap" }}>
        {markdown}
      </pre>
    </div>
  );
}
