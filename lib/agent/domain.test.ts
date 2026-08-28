import { describe, expect, it } from "vitest";
import { inferDomain, domainPromptLines } from "./domain";
import type { RouteFact } from "@/lib/graph/routeInventory";

function route(over: Partial<RouteFact>): RouteFact {
  return {
    path: "/api/x", file: "app/api/x/route.ts", methods: ["GET"],
    authenticated: true, machineGated: false, ownershipFiltered: false,
    tables: [], ...over,
  } as RouteFact;
}

describe("inferDomain", () => {
  it("reads a multi-tenant product as separated by its tenant column", () => {
    const d = inferDomain(
      ["invoices", "workspaces", "workspace_members"],
      [route({ tables: ["invoices"] })],
      ["id", "workspace_id", "user_id", "amount"],
    );
    expect(d.tenancy).toBe("multi_tenant");
    expect(d.tenantKey).toBe("workspace_id");
    expect(d.handlesMoney).toBe(true);
  });

  it("prefers the tenant boundary over the user one when both exist", () => {
    // An app with both is separated by workspace. Treating user_id as the
    // boundary would under-report the cross-tenant read we care most about.
    const d = inferDomain(["invoices"], [], ["user_id", "organization_id"]);
    expect(d.tenantKey).toBe("organization_id");
    expect(d.tenancy).toBe("multi_tenant");
  });

  it("says unknown rather than guessing when no schema was read", () => {
    // Guessing "each row belongs to one user" in a workspace product is the
    // assumption that makes a cross-tenant leak invisible.
    const d = inferDomain(["invoices"], [], []);
    expect(d.tenancy).toBe("unknown");
    expect(d.tenantKey).toBeNull();
  });

  it("ranks entities by how many routes actually reach them", () => {
    const d = inferDomain(
      ["audit_logs", "invoices"],
      [route({ tables: ["invoices"] }), route({ path: "/api/y", tables: ["invoices"] })],
      [],
    );
    expect(d.entities[0]).toBe("invoices");
  });

  it("counts in English", () => {
    const one = inferDomain(["profiles"], [], []);
    expect(one.summary).toContain("1 table holds");
    const many = inferDomain(["profiles", "messages"], [], []);
    expect(many.summary).toContain("2 tables hold");
  });

  it("notices roles and personal data", () => {
    const d = inferDomain(["memberships", "profiles", "messages"], [], ["role"]);
    expect(d.hasRoles).toBe(true);
    expect(d.sensitive).toContain("profiles");
    expect(d.sensitive).toContain("messages");
  });
});

describe("domainPromptLines", () => {
  it("tells the model what the boundary is, not just what exists", () => {
    const lines = domainPromptLines(
      inferDomain(["invoices"], [], ["workspace_id", "amount"]),
    );
    expect(lines.join("\n")).toContain("workspace_id");
    expect(lines.join("\n")).toMatch(/crosses customers/);
  });

  it("stays short enough to leave room for the routes", () => {
    const lines = domainPromptLines(
      inferDomain(
        ["invoices", "payments", "users", "profiles", "memberships", "messages", "documents"],
        [],
        ["workspace_id", "role"],
      ),
    );
    // The token doctrine caps the user prompt; every line here is a line not
    // spent describing a route.
    expect(lines.length).toBeLessThanOrEqual(5);
  });
});
