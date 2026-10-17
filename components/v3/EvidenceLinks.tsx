import type { Chain, Link } from "@/lib/chain/evidenceChain";

/**
 * An issue read the way an attacker works through it (lib/chain/evidenceChain.ts):
 * who can reach it, whether the check is missing, whether it was reproduced,
 * whether someone is trying it. Each state is said in words; "Unknown" means
 * not read, never cleared. It orders and explains; it never sets the status.
 */
const STATE: Record<Link["state"], { label: string; tone: string }> = {
  met: { label: "Met", tone: " ok" },
  open: { label: "Not yet", tone: " warn" },
  unknown: { label: "Unknown", tone: "" },
};

function evidence(link: Link) {
  // The self-check request is shown in full just below; do not repeat it here.
  if (link.id === "proof" && link.state === "open") return "Not yet. The harmless request below shows it on your preview app.";
  return link.evidence;
}

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
              <span className={`v3-tag${STATE[link.state].tone}`}>{STATE[link.state].label}</span>
            </div>
            <p className="v3-small" style={{ marginTop: 4, overflowWrap: "anywhere" }}>{evidence(link)}</p>
          </li>
        ))}
      </ol>
      {chain.next ? <p className="v3-small" style={{ marginTop: 4 }}><b style={{ fontWeight: 500 }}>Next:</b> {chain.next}</p> : null}
    </section>
  );
}
