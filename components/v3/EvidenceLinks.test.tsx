import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { evidenceChain } from "@/lib/chain/evidenceChain";
import { EvidenceLinks } from "./EvidenceLinks";

// The four links a founder reads on each issue: who can reach it, whether the
// check is missing, whether it was reproduced, whether someone is trying it.
const finding = { severity: "CRITICAL" as const, confidence: "inferred" as const, attackClass: "missing_authentication",
  entry: "/api/notes/[id]", claims: [], confirmed: true };

describe("EvidenceLinks", () => {
  const chain = evidenceChain(finding, { calledBy: ["components/Note.tsx"], trafficConnected: false });
  const html = renderToStaticMarkup(<EvidenceLinks chain={chain} />);

  // Design pass 2026-10-20: a link that holds is the risk standing up, so it
  // reads "Yes" in the critical tone, never a reassuring green.
  it("shows each link with its state in words, not color alone, and a holding link in the critical tone", () => {
    for (const t of ["A stranger can reach it", "The check is missing", "It was reproduced", "Someone is trying it"]) expect(html).toContain(t);
    expect(html).toContain('<span class="v3-tag crit">Yes</span>');
    expect(html).not.toContain("v3-tag ok");
    expect(html).toContain("Not yet");
    expect(html).toContain("Unknown");
    expect(html).toMatch(/2 of 4/);
  });

  it("points the proof link at the request below instead of repeating it", () => {
    expect(html).toContain("The harmless request below shows it");
    expect(html).not.toContain("curl");
  });

  // 107: the founder sees what their agent reported, labeled as reported,
  // never hidden behind "Not yet" and never shown as met.
  it("shows the agent's reported self-check in full, labeled Reported", () => {
    const reported = renderToStaticMarkup(<EvidenceLinks chain={evidenceChain(finding, { trafficConnected: false,
      selfCheck: { status: 404, host: "localhost:3000", reportedAt: "2026-10-17T12:00:00.000Z" } })} />).replace(/<[^>]+>/g, " ");
    expect(reported).toContain("Your agent ran the check on localhost:3000");
    expect(reported).toContain("Reported");
    expect(reported).not.toContain("The harmless request below shows it");
    expect(reported).not.toContain("Not yet");
  });

  it("names the next safe step and carries no dashes", () => {
    const candidate = renderToStaticMarkup(<EvidenceLinks chain={evidenceChain({ ...finding, confirmed: false }, { trafficConnected: true })} />);
    expect(candidate.replace(/<[^>]+>/g, "")).toMatch(/Next: Ask your agent to prove or refute it/);
    expect(html.replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]| - /);
  });
});
