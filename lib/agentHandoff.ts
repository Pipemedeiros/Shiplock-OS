import type { FixKind } from "@/lib/agent/findings";

/**
 * The instruction a customer pastes into their own agent (Claude Code, Codex)
 * to work one finding through ShipLock's MCP tools. The agent proposes; the
 * person reviews the diff and merges. An authorization decision is the
 * person's (AGENTS.md: no machine-authored business policy).
 */
export function agentFixPrompt(f: { id: string; title: string; repository: string | null; fixKind: FixKind }): string {
  const where = f.repository ? ` in ${f.repository}` : "";
  const lines = [
    `Use ShipLock to fix finding ${f.id}${where}: "${f.title}".`,
    "1. Call get_security_context for this repository and keep every guardrail it lists.",
    `2. Call get_fix with id ${f.id} and read the fix it describes.`,
    f.fixKind === "manual"
      ? "3. This is an authorization decision. Propose the smallest change and explain the tradeoff; I decide."
      : "3. Make that change in my working tree, run the tests, and show me the diff.",
    "Do not merge, deploy, or apply anything to a database. ShipLock rechecks the pull request.",
  ];
  return lines.join("\n");
}
