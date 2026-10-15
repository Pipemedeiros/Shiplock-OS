import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

import { AiStep, InstallGitHubLink, OnboardingFlow, Working } from "./OnboardingFlow";

describe("onboarding asks for the customer's AI after the first audit (10B-2b)", () => {
  it("shows Your AI as the fifth step, after the first audit", () => {
    const html = renderToStaticMarkup(<OnboardingFlow connected={false} initialRepos={[]} listError={null} />);
    expect(html.indexOf("First audit")).toBeGreaterThan(-1);
    expect(html.indexOf("Your AI")).toBeGreaterThan(html.indexOf("First audit"));
  });

  it("explains the first audit needs no AI, is skippable, and embeds the approval form", () => {
    const html = renderToStaticMarkup(<AiStep onDone={() => {}} />);
    expect(html).toContain("Connect the AI you already use to reason about attack paths");
    expect(html).toContain("Skip for now");
    expect(html).toContain("Every pull request still needs your click");
  });
});

// Felipe 2026-10-14: "The user has to know when they press something and when
// something is being done ... responsive." Every press answers at once.
describe("onboarding answers every press", () => {
  it("the GitHub install link says it is opening GitHub once pressed", () => {
    const idle = renderToStaticMarkup(<InstallGitHubLink opening={false} onOpen={() => {}} />);
    expect(idle).toContain("Install the GitHub App");
    expect(idle).not.toContain("aria-busy");
    const opening = renderToStaticMarkup(<InstallGitHubLink opening onOpen={() => {}} />);
    expect(opening).toContain("Opening GitHub");
    expect(opening).toContain('aria-busy="true"');
    expect(opening).toContain("v3-spin");
  });

  it("the last step's button shows it is opening, and cannot be pressed twice", () => {
    const html = renderToStaticMarkup(<AiStep onDone={() => {}} pending />);
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>.*Opening/);
    expect(renderToStaticMarkup(<AiStep onDone={() => {}} />)).toContain("Open the results");
  });

  it("a wait is a live status with a moving indicator, not static text", () => {
    const html = renderToStaticMarkup(<Working>Reading the repository</Working>);
    expect(html).toContain('role="status"');
    expect(html).toContain("v3-spin");
    expect(html).toContain("Reading the repository");
  });

  it("the stack and first audit waits use it", () => {
    const src = readFileSync("components/v3/OnboardingFlow.tsx", "utf8");
    expect(src).toMatch(/<Working>Reading the repository<\/Working>/);
    expect(src).toMatch(/<Working>Cloning and reading the repository<\/Working>/);
    expect(src).toMatch(/<Working>Reading your repositories<\/Working>/);
  });
});
