import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SecurityLoop } from "./SecurityLoop";
import type { LoopStage } from "@/lib/securityLoop";

const stages: LoopStage[] = [
  { key: "read", title: "Read", state: "working", headline: "Reading now", detail: "412 files read", href: "/dashboard/activity" },
  { key: "attack", title: "Attack", state: "waiting", headline: "3 tasks wait for your agent", detail: "x", href: "/dashboard/coverage" },
  { key: "map", title: "Map", state: "done", headline: "38 routes mapped", detail: "None exposed in the code read", href: "/dashboard#map" },
  { key: "fix", title: "Fix", state: "attention", headline: "5 open issues", detail: "y", href: "/dashboard/risks", action: "View issues" },
  { key: "watch", title: "Watch", state: "off", headline: "Not watching yet", detail: "z", href: "/dashboard/coverage" },
];

describe("security loop strip", () => {
  const html = renderToStaticMarkup(<SecurityLoop stages={stages} />);

  it("lists the five stages in order as a labelled list", () => {
    expect(html).toMatch(/<ol[^>]*aria-label="Security loop"/);
    const order = ["Read", "Attack", "Map", "Fix", "Watch"].map((t) => html.indexOf(`>${t}<`));
    expect(order.every((i, k) => i > 0 && (k === 0 || i > order[k - 1]))).toBe(true);
  });

  it("names every state in words, not colour alone", () => {
    for (const word of ["In progress", "Waiting", "Done", "Needs you", "Not run"]) expect(html).toContain(word);
  });

  it("links each stage to where its evidence lives, with its action", () => {
    expect(html).toContain('href="/dashboard/risks"');
    expect(html).toContain("View issues");
  });
});

// Design pass 2026-10-20: the five stages read as one loop, numbered, with
// the connector after a finished stage drawn solid.
const stage = (key: LoopStage["key"], title: string, state: LoopStage["state"]): LoopStage =>
  ({ key, title, state, headline: `${title} headline`, detail: "detail", href: "/dashboard" } as LoopStage);

describe("SecurityLoop as one loop", () => {
  const html = renderToStaticMarkup(<SecurityLoop stages={[stage("read", "Read", "done"), stage("attack", "Attack", "waiting"),
    stage("map", "Map", "off"), stage("fix", "Fix", "attention"), stage("watch", "Watch", "working")]} />);

  it("numbers the stages for the eye, leaving the list's own numbering to screen readers", () => {
    for (const [n, t] of [[1, "Read"], [2, "Attack"], [3, "Map"], [4, "Fix"], [5, "Watch"]] as const) {
      expect(html).toContain(`<span class="v3-loop-n" aria-hidden="true">${n}</span>${t}`);
    }
  });

  it("marks a finished stage so the connector after it is solid", () => {
    expect(html.match(/<li class="done">/g)).toHaveLength(1);
    expect(html.match(/<li class="">/g)).toHaveLength(4);
  });
});
