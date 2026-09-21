import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import Landing from "./page";

describe("Section 4 / Step 4A: founder-facing product truth", () => {
  it("states current coverage and approval boundaries without presenting planned proof as shipped", () => {
    const html = renderToStaticMarkup(<Landing />);

    expect(html).toContain("Supported Next.js route handlers");
    expect(html).toContain("checks supported paths from route");
    expect(html).toContain("what it could not read");
    expect(html).toContain("ShipLock never merges or deploys it");
    expect(html).toContain("not enabled in the preview today");
    expect(html).toContain("currently in development");

    expect(html).not.toContain("Every route handler");
    expect(html).not.toContain("follows each entry point");
    expect(html).not.toContain("read everything");
    expect(html).not.toContain("first audit takes a few minutes");
    expect(html).not.toContain("only after the change has been tested");
    expect(html).not.toContain("The leak is reproduced rather than inferred");
    expect(html).not.toContain("1,140 workspaces");
  });
});
