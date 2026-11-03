import type { Guardrails, GuardrailKind } from "@/lib/guardrails/guardrails";

const LABEL: Record<GuardrailKind, string> = {
  requires_signed_in_caller: "Requires a signed-in caller",
  scopes_rows_to_caller: "Rows scoped to the caller",
  requires_machine_secret: "Requires a secret or signature",
};

/** The rules a repository must keep, as the PR check and MCP see them. */
export function GuardrailList({ guardrails }: { guardrails: Guardrails | null }) {
  if (!guardrails) {
    return <p className="v3-small">Guardrails are not known yet. They come from the first audit&apos;s route facts.</p>;
  }
  if (guardrails.rules.length === 0) {
    return <p className="v3-small">The last audit read no control it could turn into a rule. That does not mean none are needed; see what was not covered below.</p>;
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      <p className="v3-small">
        Controls your code has today. ShipLock&apos;s pull request check blocks a change that removes one, and your coding
        agent can read the same list over MCP before it edits.
      </p>
      <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 8 }}>
        {guardrails.rules.slice(0, 40).map((rule) => (
          <li key={rule.id} className="v3-between" style={{ gap: 12, alignItems: "flex-start" }}>
            <span className="v3-mono" style={{ fontSize: 13, wordBreak: "break-all" }}>{rule.route}</span>
            <span className="v3-small" style={{ whiteSpace: "nowrap" }}>{LABEL[rule.kind]}</span>
          </li>
        ))}
      </ul>
      {guardrails.rules.length > 40 ? <p className="v3-small">And {guardrails.rules.length - 40} more.</p> : null}
    </div>
  );
}
