import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: () => {} }) }));
import { AgentPrsView } from "./AgentPrsPanel";
import { AGENT_PRS_RISKS } from "@/lib/agentPrs";

// 103 (Felipe 2026-10-15): the founder chooses, per repository, after reading the risks.
const noop = () => {};
const view = (props: Partial<Parameters<typeof AgentPrsView>[0]> = {}) => renderToStaticMarkup(
  <AgentPrsView repositories={[{ id: "r1", fullName: "acme/app", since: null }]} open={null} accepted={false} busy={false} error=""
    onOpen={noop} onAccept={noop} onGrant={noop} onRevoke={noop} {...props} />);

describe("AgentPrsView", () => {
  it("is off by default and says what turning it on means", () => {
    const html = view();
    expect(html).toContain("acme/app");
    expect(html).toContain("Off");
    expect(html).not.toContain(AGENT_PRS_RISKS[1]);
  });
  it("shows every risk and needs the box ticked before it turns on", () => {
    const html = view({ open: "r1" });
    for (const risk of AGENT_PRS_RISKS) expect(html).toContain(risk.replace(/'/g, "&#x27;"));
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Let my agent open pull requests<\/button>/);
    expect(view({ open: "r1", accepted: true })).not.toMatch(/<button[^>]*disabled=""[^>]*>Let my agent open pull requests/);
  });
  it("shows since when it is on, with a way to turn it off", () => {
    const html = view({ repositories: [{ id: "r1", fullName: "acme/app", since: "2026-10-15T10:00:00Z" }] });
    expect(html).toContain("On since");
    expect(html).toContain("Turn off");
  });
  it("speaks without dashes", () => {
    expect(view({ open: "r1" }).replace(/acme\/app/g, "")).not.toMatch(/[–—]/);
  });
});
