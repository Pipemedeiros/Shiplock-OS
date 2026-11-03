import { Children, isValidElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { DirectRepositoryAssociationView } from "./DirectRepositoryAssociation";
import { PostgresPanel } from "./PostgresPanel";
import { type DirectRepositoryConfirmationState, type DirectRepositoryContext } from "@/lib/connections/directRepositoryConfirmation";

const id = "22222222-2222-4222-8222-222222222222";
const context: DirectRepositoryContext = { available: true, databaseDisplay: "db.example/app", connectionFingerprint: "a".repeat(64), installationId: "42",
  githubConnectedAt: "2026-09-17T09:00:00Z", repositories: [{ id, fullName: "acme/app", githubRepoId: "7" }], bindings: [] };
const actions = () => ({ review: vi.fn(), cancel: vi.fn(), approve: vi.fn().mockResolvedValue(undefined), load: vi.fn().mockResolvedValue(undefined) });
function view(state: DirectRepositoryConfirmationState, disabled = false) {
  const handlers = actions(); const tree = DirectRepositoryAssociationView({ state, actions: handlers, disabled });
  return { handlers, tree, html: renderToStaticMarkup(tree) };
}
type Button = { children?: ReactNode; onClick: () => void; disabled: boolean };
function buttons(node: ReactNode): Button[] {
  return Children.toArray(node).flatMap((child) => {
    if (!isValidElement<{ children?: ReactNode }>(child)) return [];
    return child.type === "button" ? [child.props as Button] : buttons(child.props.children);
  });
}
function click(tree: ReactNode, label: string) {
  const button = buttons(tree).find((candidate) => Children.toArray(candidate.children).join("") === label);
  expect(button).toBeDefined(); button!.onClick();
}

describe("rendered association controls", () => {
  it("describes customer confirmation without deployment or security verification and hides opaque IDs", () => {
    const { html } = view({ status: "ready", context });
    expect(html).toContain("Current database:"); expect(html).toContain("db.example/app");
    expect(html).toContain("not proof of a deployment or a security check"); expect(html).toContain("Cross-layer analysis is not enabled");
    expect(html).toContain("Not confirmed"); expect(html).not.toContain(context.connectionFingerprint); expect(html).not.toContain(id);
  });

  it("review clicks only request review, never approval", () => {
    const { tree, handlers, html } = view({ status: "ready", context });
    click(tree, "Review association"); expect(handlers.review).toHaveBeenCalledWith(id, "confirm");
    expect(handlers.approve).not.toHaveBeenCalled(); expect(html).not.toContain(">Confirm association<");
  });

  it("confirmed rows offer review of removal, not immediate deletion", () => {
    const { tree, handlers, html } = view({ status: "ready", context: { ...context, bindings: [{ repositoryId: id, method: "customer_confirmed", confirmedAt: "2026-09-17T10:00:00Z" }] } });
    expect(html).toContain("Confirmed by you"); click(tree, "Review removal");
    expect(handlers.review).toHaveBeenCalledWith(id, "remove"); expect(handlers.approve).not.toHaveBeenCalled();
  });

  it.each(["confirm", "remove"] as const)("%s review wires separate approval and cancel controls", (action) => {
    const { tree, handlers, html } = view({ status: "review", context, decision: { repositoryId: id, action } });
    click(tree, "Cancel"); expect(handlers.cancel).toHaveBeenCalledOnce(); expect(handlers.approve).not.toHaveBeenCalled();
    click(tree, action === "confirm" ? "Confirm association" : "Remove association"); expect(handlers.approve).toHaveBeenCalledOnce();
    expect(html).not.toContain("Reload associations");
    if (action === "remove") expect(html).toContain("does not disconnect the database");
  });

  it.each(["unavailable", "stale", "unconfigured"] as const)("%s renders no confirmation state or mutation control", (status) => {
    const { tree, handlers, html } = view({ status, message: "Reload to review again." });
    expect(html).not.toContain("Confirmed by you"); expect(html).not.toContain("acme/app"); expect(html).not.toContain(">Confirm association<");
    click(tree, "Reload associations"); expect(handlers.load).toHaveBeenCalledOnce(); expect(handlers.approve).not.toHaveBeenCalled();
  });

  it.each(["loading", "saving"] as const)("%s announces progress and disables reload", (status) => {
    const { tree, html } = view({ status });
    expect(html).toContain('role="status"'); expect(html).toContain('aria-live="polite"'); expect(html).toContain('aria-busy="true"');
    expect(buttons(tree).every((button) => button.disabled)).toBe(true); expect(html).not.toContain("Review association");
  });

  it("disables review/approval/cancel/reload during an existing connection operation", () => {
    for (const state of [{ status: "ready", context }, { status: "review", context, decision: { repositoryId: id, action: "confirm" } }] as DirectRepositoryConfirmationState[]) {
      const { tree } = view(state, true); expect(buttons(tree).every((button) => button.disabled)).toBe(true);
    }
  });

  it("empty selected repositories route to GitHub setup without inventing an association", () => {
    const { html } = view({ status: "ready", context: { ...context, repositories: [] } });
    expect(html).toContain('href="/onboarding"'); expect(html).not.toContain("Review association");
  });

  it("escapes database labels and allows long repository names to wrap", () => {
    const { html } = view({ status: "ready", context: { ...context, databaseDisplay: "<script>private()</script>", repositories: [{ ...context.repositories[0], fullName: `acme/${"x".repeat(100)}` }] } });
    expect(html).not.toContain("<script>"); expect(html).toContain("&lt;script&gt;"); expect(html).toContain("overflow-wrap:anywhere");
  });

  it("the existing connected panel renders the actual wrapper's loading snapshot beside connection controls", () => {
    const html = renderToStaticMarkup(<PostgresPanel connected display="db.example/app" />);
    expect(html).toContain("Check policies now"); expect(html).toContain("Disconnect");
    expect(html).toContain("Loading repository associations"); expect(html).not.toContain("Confirmed by you");
    expect(html).not.toContain("Review association");
  });

  it("the disconnected panel keeps its original setup without asking for repository confirmation", () => {
    const html = renderToStaticMarkup(<PostgresPanel connected={false} display={null} />);
    expect(html).not.toContain("Database repository associations"); expect(html).not.toContain("Confirmed by you");
    expect(html).toContain("read-only role");
  });
});
