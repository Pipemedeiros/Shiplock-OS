/**
 * The landing hero: an example session in which the customer's own agent uses
 * ShipLock's MCP tools (Felipe 2026-10-21: the agent is the one reading
 * ShipLock). Tool names are the real ones from lib/mcpTools.ts; the repository
 * and finding are an example and say so. The session ends at the customer's
 * click, because a pull request needs one. Pure CSS motion, none when the
 * reader asks for reduced motion.
 */
const LINES: { k: "tool" | "out" | "crit" | "code" | "done"; t: string; s?: string }[] = [
  { k: "tool", t: "shiplock", s: "get_security_context" },
  { k: "out", t: "41 routes read · 1 critical · 2 files not read" },
  { k: "tool", t: "shiplock", s: "list_findings" },
  { k: "crit", t: "CRITICAL  GET /api/invoices/[id]", s: "any signed-in user reads another workspace's invoices" },
  { k: "tool", t: "Read", s: "app/api/invoices/[id]/route.ts" },
  { k: "code", t: '14  .from("invoices").select("*").eq("id", id)', s: "no workspace filter on this query" },
  { k: "tool", t: "shiplock", s: "get_fix" },
  { k: "out", t: 'add .eq("workspace_id", session.workspaceId) · mechanical' },
  { k: "done", t: "Proposed. Open the pull request in ShipLock: one click, one receipt." },
];

export function AgentSession() {
  return (
    <figure className="v3-sess" aria-label="Example: a coding agent using ShipLock over MCP">
      <div className="v3-sess-bar">
        <span className="v3-sess-dots" aria-hidden="true"><i /><i /><i /></span>
        <span className="v3-mono">claude · ~/acme-app</span>
        <span className="v3-sess-tag v3-mono">example</span>
      </div>
      <div className="v3-sess-body v3-mono">
        <p className="v3-sess-prompt"><span aria-hidden="true">›</span> <span className="v3-sess-typed">check this repo with ShipLock, fix the worst one</span></p>
        {LINES.map((l, i) => (
          <p key={i} className={`v3-sess-line v3-sess-${l.k}`} style={{ ["--i" as string]: i + 1 }}>
            {l.k === "tool" ? (
              <><span className="v3-sess-bullet" aria-hidden="true">●</span> <b>{l.t}</b>{l.t === "shiplock" ? " · " : " "}<span>{l.s}</span></>
            ) : l.k === "done" ? (
              <><span className="v3-sess-bullet" aria-hidden="true">●</span> {l.t}</>
            ) : (
              <><span className="v3-sess-elbow" aria-hidden="true">└</span> <span>{l.t}</span>{l.s ? <small>{l.s}</small> : null}</>
            )}
          </p>
        ))}
      </div>
    </figure>
  );
}
