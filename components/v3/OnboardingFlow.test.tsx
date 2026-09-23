import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

import { AiStep, OnboardingFlow } from "./OnboardingFlow";

describe("onboarding asks for the customer's AI after the first audit (10B-2b)", () => {
  it("shows Your AI as the fifth step, after the first audit", () => {
    const html = renderToStaticMarkup(<OnboardingFlow connected={false} initialRepos={[]} listError={null} />);
    expect(html.indexOf("First audit")).toBeGreaterThan(-1);
    expect(html.indexOf("Your AI")).toBeGreaterThan(html.indexOf("First audit"));
  });

  it("explains the first scan was ours, is skippable, and embeds the approval form", () => {
    const html = renderToStaticMarkup(<AiStep onDone={() => {}} />);
    expect(html).toContain("Your first scan was on us");
    expect(html).toContain("Skip for now");
    expect(html).toContain("Every pull request still needs your click");
  });
});
