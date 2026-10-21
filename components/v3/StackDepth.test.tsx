import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { connectionFor, StackConnection } from "./StackDepth";

// Felipe (2026-09-29): ShipLock is for any stack. A provider we detect but
// cannot read live yet is named and marked "coming soon", never hidden and
// never offered as if it worked.
describe("connectionFor", () => {
  it("offers a connection only where a live read exists", () => {
    expect(connectionFor({ id: "supabase", kind: "database" })).toMatchObject({ state: "available", provider: "Supabase" });
    expect(connectionFor({ id: "supabase-auth", kind: "auth" })).toMatchObject({ state: "available", provider: "Supabase" });
    expect(connectionFor({ id: "postgres", kind: "database" })).toMatchObject({ state: "available", provider: "Postgres" });
    expect(connectionFor({ id: "prisma", kind: "database" })).toMatchObject({ state: "available", provider: "Postgres" });
  });

  it("marks detected databases, auth, payments and hosting we cannot read yet as coming soon", () => {
    for (const tool of [
      { id: "firebase", kind: "database" }, { id: "mongo", kind: "database" }, { id: "mysql", kind: "database" },
      { id: "firebase-auth", kind: "auth" }, { id: "clerk", kind: "auth" }, { id: "stripe", kind: "payments" },
      { id: "vercel", kind: "hosting" }, { id: "cloudflare", kind: "hosting" },
    ] as const) {
      expect(connectionFor(tool).state, tool.id).toBe("coming_soon");
    }
  });

  it("makes no connection claim for kinds that have none planned", () => {
    expect(connectionFor({ id: "resend", kind: "email" })).toEqual({ state: "none" });
  });

  it("renders a link for an available connection and a plain label for coming soon", () => {
    expect(renderToStaticMarkup(<StackConnection connection={connectionFor({ id: "supabase", kind: "database" })} />))
      .toMatch(/href="\/dashboard\/settings"[^>]*>Connect Supabase/);
    const soon = renderToStaticMarkup(<StackConnection connection={connectionFor({ id: "mongo", kind: "database" })} />);
    expect(soon).toContain("Live connection coming soon");
    expect(soon).not.toContain("href");
    expect(renderToStaticMarkup(<StackConnection connection={{ state: "none" }} />)).toBe("");
  });

  // A founder who already connected the database must not be told to connect it.
  it("says connected, with no button, once that provider is connected", () => {
    const connected = new Set(["Supabase"] as const);
    expect(connectionFor({ id: "supabase", kind: "database" }, connected)).toEqual({ state: "connected", provider: "Supabase" });
    expect(connectionFor({ id: "prisma", kind: "database" }, connected)).toMatchObject({ state: "available", provider: "Postgres" });
    const html = renderToStaticMarkup(<StackConnection connection={{ state: "connected", provider: "Supabase" }} />);
    expect(html).toContain("Supabase connected read only");
    expect(html).not.toContain("href");
  });
});
