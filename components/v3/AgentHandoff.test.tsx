import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { AgentHandoff } from "./AgentHandoff";

describe("agent handoff", () => {
  const html = renderToStaticMarkup(<AgentHandoff finding={{ id: "f-1", title: "Orders leak", repository: "acme/app", fixKind: "manual" }} />);
  it("shows the instruction to paste into the agent", () => {
    expect(html).toContain("Hand it to your agent");
    expect(html).toContain("get_fix with id f-1");
  });
  it("offers a labelled copy button and a status line for its result", () => {
    expect(html).toMatch(/<button[^>]*>Copy instruction<\/button>/);
    expect(html).toMatch(/role="status"/);
  });
  it("points to where the agent is connected", () => {
    expect(html).toContain('href="/dashboard/settings"');
  });
});
