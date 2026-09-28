import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { RepairPreviewView } from "./RepairPreview";

describe("RepairPreviewView (Q13)", () => {
  it("shows every file, added or changed, the target, and that tests were not run", () => {
    const html = renderToStaticMarkup(<RepairPreviewView busy={false} onOpen={() => {}} preview={{ status: "planned", lane: "Dependency update",
      repository: "acme/app", base: "main", branch: "shiplock/x", title: "Bump lodash", body: "Why", tests: "not run by ShipLock",
      files: [{ path: "package.json", change: "edit", before: "{\"a\":1}", after: "{\"a\":2}" }, { path: "lib/new.ts", change: "add", before: null, after: "new" }] }} />);
    expect(html).toContain("Bump lodash");
    expect(html).toContain("acme/app");
    expect(html).toContain("new branch shiplock/x into main");
    expect(html).toContain("Changes package.json");
    expect(html).toContain("Adds lib/new.ts");
    expect(html).toContain("Tests were not run by ShipLock");
    expect(html).toContain("Open pull request");
    expect(html).not.toMatch(/[–—]/);
  });
  it("says when a file name's date is set at click (Q8)", () => {
    const html = renderToStaticMarkup(<RepairPreviewView busy={false} onOpen={() => {}} preview={{ status: "planned", lane: "Fix",
      repository: "acme/app", base: "main", branch: "shiplock/fix-x", title: "Fix", body: "Why", tests: "not run by ShipLock",
      files: [{ path: "supabase/migrations/20260928120000_shiplock_x.sql", change: "add", before: null, after: "sql", nameSetAtClick: true },
        { path: "lib/a.ts", change: "edit", before: "a", after: "b" }] }} />);
    expect(html.match(/date in the file name is set when you open the pull request/g)).toHaveLength(1);
    expect(html).not.toMatch(/[–—]/);
  });
  it("links an already open pull request and explains an unavailable one, with no open button", () => {
    const open = renderToStaticMarkup(<RepairPreviewView busy={false} onOpen={() => {}} preview={{ status: "already_open", url: "https://github.com/acme/app/pull/3" }} />);
    expect(open).toContain("https://github.com/acme/app/pull/3");
    expect(open).not.toContain("Open pull request");
    const none = renderToStaticMarkup(<RepairPreviewView busy={false} onOpen={() => {}} preview={{ status: "unavailable", code: "no_changes" }} />);
    expect(none).toMatch(/nothing to change/i);
    expect(none).not.toContain("Open pull request");
  });
});
