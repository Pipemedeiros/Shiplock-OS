import type { Chain, Link } from "@/lib/chain/evidenceChain";

/**
 * An issue read the way an attacker works through it (lib/chain/evidenceChain.ts):
 * who can reach it, whether the check is missing, whether it was reproduced,
 * whether someone is trying it. Each state is said in words; "Unknown" means
 * not read, never cleared. It orders and explains; it never sets the status.
 */
// Each link is a step of the attack, so one that holds is the risk standing
// up: "Yes" in the critical tone, never green.
const STATE: Record<Link["state"], { label: string; tone: string }> = {
  met: { label: "Yes", tone: " crit" },
  open: { label: "Not yet", tone: "" },
  unknown: { label: "Unknown", tone: "" },
};

function evidence(link: Link) {
  // The self-check request is shown in full just below; do not repeat it here.
  // An agent's report is shown in full: it is what the founder came to read.
  if (link.id === "proof" && link.state === "open" && !link.reported) return "Not yet. The harmless request below shows it on your preview app.";
  return link.evidence;
}

// A report is the agent's word, not ShipLock's observation: its own label.
const label = (link: Link) => (link.reported ? { label: "Reported", tone: " warn" } : STATE[link.state]);

export function EvidenceLinks({ chain }: { chain: Chain }) {
  return (
    <section aria-label="Evidence chain" style={{ marginBottom: 16 }}>
      <div className="v3-between">
        <b style={{ fontWeight: 500 }}>What backs this</b>
        <span className="v3-small">{chain.met} of 4</span>
      </div>
      <ol style={{ listStyle: "none", padding: 0, margin: "8px 0 0" }}>
        {chain.links.map((link) => (
          <li key={link.id} style={{ padding: "8px 0", borderTop: "1px solid var(--line)" }}>
            <div className="v3-between" style={{ gap: 8 }}>
              <span>{link.title}</span>
              <span className={`v3-tag${label(link).tone}`}>{label(link).label}</span>
            </div>
            <p className="v3-small" style={{ marginTop: 4, overflowWrap: "anywhere" }}>{evidence(link)}</p>
          </li>
        ))}
      </ol>
      {chain.next ? <p className="v3-small" style={{ marginTop: 4 }}><b style={{ fontWeight: 500 }}>Next:</b> {chain.next}</p> : null}
    </section>
  );
}
