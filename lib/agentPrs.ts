/**
 * Agent pull requests (Felipe 2026-10-15): the customer may let their own
 * coding agent ask ShipLock to open fix pull requests for one repository.
 * ShipLock has no agent; it is the harness the customer's agent drives.
 *
 * Why the customer turns it on in the dashboard and never through a token:
 * an agent follows text it reads, including text an attacker planted (indirect
 * prompt injection, Greshake et al. 2023), and an agent holding private data,
 * untrusted input and a way to act is the risk OWASP's LLM06 "excessive
 * agency" and Willison's "lethal trifecta" describe. So the right is scoped to
 * one repository, to fixes ShipLock rates as mechanical, to the click's daily
 * cap, revocable at once, recorded on every receipt, and never a merge.
 *
 * The acknowledgement is versioned: changing what the customer agrees to
 * means a new version, and the database accepts only the current one (103).
 */
export const AGENT_PRS_ACK = "agent-prs-v1";

export const AGENT_PRS_RISKS = [
  "Your agent decides when to open a pull request. ShipLock has no agent of its own; it opens what yours asks for.",
  "Agents follow text they read, including text an attacker planted in an issue, a dependency or a web page. A pull request opened this way can be wrong.",
  "Only fixes ShipLock rates as mechanical can be opened this way. Anything about who may see what stays your decision.",
  "Each one opens on a new branch and runs your own CI. ShipLock never merges; review every one before you merge it.",
  "The daily limit on fixes still applies, and turning this off stops new requests at once.",
] as const;
