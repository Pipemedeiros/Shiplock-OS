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

  it("shows each link with its state in words, not color alone", () => {
    for (const t of ["A stranger can reach it", "The check is missing", "It was reproduced", "Someone is trying it"]) expect(html).toContain(t);
    expect(html).toContain("Met");
    expect(html).toContain("Not yet");
    expect(html).toContain("Unknown");
    expect(html).toMatch(/2 of 4/);
  });

  it("points the proof link at the request below instead of repeating it", () => {
    expect(html).toContain("The harmless request below shows it");
    expect(html).not.toContain("curl");
  });

  it("names the next safe step and carries no dashes", () => {
    const candidate = renderToStaticMarkup(<EvidenceLinks chain={evidenceChain({ ...finding, confirmed: false }, { trafficConnected: true })} />);
    expect(candidate.replace(/<[^>]+>/g, "")).toMatch(/Next: Ask your agent to prove or refute it/);
    expect(html.replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]| - /);
  });
});
