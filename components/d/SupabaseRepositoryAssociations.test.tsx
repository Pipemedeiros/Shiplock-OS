import { Children, isValidElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { SupabaseRepositoryAssociationView, SupabaseRepositoryAssociations } from "./SupabaseRepositoryAssociations";
import { DirectRepositoryAssociationView } from "./DirectRepositoryAssociation";
import { SupabasePanel } from "./SupabasePanel";
import type { SupabaseRepositoryConfirmationState } from "@/lib/connections/supabaseRepositoryConfirmation";

const id = "22222222-2222-4222-8222-222222222222";
const ready = (collector: "supabase-management" | "supabase-scan"): SupabaseRepositoryConfirmationState => ({ status: "ready", context: {
  available: true, collector, projectRef: "project-a", endpointUrl: collector === "supabase-scan" ? "https://project-a.supabase.co" : null,
  connectionFingerprint: "a".repeat(64), installationId: "42", githubConnectedAt: "2026-09-17T09:00:00Z",
  repositories: [{ id, fullName: "acme/app", githubRepoId: "7" }], bindings: [] } });
const actions = () => ({ review: vi.fn(), cancel: vi.fn(), approve: vi.fn().mockResolvedValue(undefined), load: vi.fn().mockResolvedValue(undefined) });
type Button = { children?: ReactNode; onClick: () => void; disabled: boolean };
function buttons(node: ReactNode): Button[] { return Children.toArray(node).flatMap((child) => !isValidElement<{ children?: ReactNode }>(child) ? []
  : child.type === "button" ? [child.props as Button] : buttons(child.props.children)); }

describe("Supabase Settings associations", () => {
  it.each(["supabase-management", "supabase-scan"] as const)("names %s separately without claiming proof", (collector) => {
    const handlers = actions(); const tree = SupabaseRepositoryAssociationView({ collector, state: ready(collector), actions: handlers, disabled: false });
    const html = renderToStaticMarkup(tree); expect(html).toContain(collector === "supabase-management" ? "Management API access" : "Endpoint scan access");
    expect(html).toContain("project-a"); expect(html).toContain("not proof of a deployment or a security check");
    expect(html).not.toContain("a".repeat(64)); expect(html).not.toContain(id);
    const rendered = DirectRepositoryAssociationView(tree.props);
    buttons(rendered).find((button) => Children.toArray(button.children).join("") === "Review association")!.onClick();
    expect(handlers.review).toHaveBeenCalledWith(id, "confirm"); expect(handlers.approve).not.toHaveBeenCalled();
  });

  it("renders unconfigured/stale states without confirmed claims or mutation controls", () => {
    for (const state of [{ status: "unconfigured" }, { status: "stale", message: "Reload first." }] as SupabaseRepositoryConfirmationState[]) {
      const html = renderToStaticMarkup(SupabaseRepositoryAssociationView({ collector: "supabase-management", state, actions: actions(), disabled: false }));
      expect(html).not.toContain("Confirmed by you"); expect(html).not.toContain("Confirm association");
    }
  });

  it("the actual wrapper exposes two independent loading states", () => {
    const html = renderToStaticMarkup(<SupabaseRepositoryAssociations disabled={false} onMutationBusyChange={vi.fn()} />);
    expect(html.match(/Loading repository associations/g)).toHaveLength(2);
    expect(html).toContain("Management API access"); expect(html).toContain("Endpoint scan access");
  });

  it("the existing Supabase panel mounts associations even when management access is disconnected", () => {
    const html = renderToStaticMarkup(<SupabasePanel connected={false} projectRef={null} configured />);
    expect(html).toContain("Connect read-only access"); expect(html).toContain("Management API access"); expect(html).toContain("Endpoint scan access");
  });

  it("external connection work disables all association controls", () => {
    const tree = SupabaseRepositoryAssociationView({ collector: "supabase-scan", state: ready("supabase-scan"), actions: actions(), disabled: true });
    expect(buttons(tree).every((button) => button.disabled)).toBe(true);
  });
});
