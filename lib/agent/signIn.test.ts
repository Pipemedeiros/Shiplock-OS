import { describe, expect, it } from "vitest";
import { appSignIn, openByDesign } from "./signIn";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { StackReport } from "./stack";

const route = (path: string, file: string, authenticated = false) =>
  ({ path, file, authenticated, tables: ["farm"] }) as unknown as RouteFact;
const stack = (tools: { id: string; kind: string }[] = []) => ({ tools, authUnknown: tools.length === 0 }) as unknown as StackReport;
const read = (files: Record<string, string>) => ({ files: Object.entries(files).map(([path, content]) => ({ path, content })), truncated: false });

// P3 (D1): release attempt 5 found 5 of its 9 false findings in apps with no
// sign-in anywhere (a single-tenant demo, a self-hosted single-user tool).
// Absence is claimed only when every sign of an account is absent and the
// whole repository was read; anything else is present or unknown.
describe("appSignIn", () => {
  const demo = read({ "src/actions/pac.ts": "export async function updatePacField(farmId) { await supabaseAdmin.from('farm').update({}) }",
    "src/lib/demo.ts": "export const DEMO_FARMER_ID = 'f1';" });

  it("is absent for an app with no auth library, no signed-in route, no users table and no sign-in code", () => {
    expect(appSignIn({ routes: [route("/api/farm", "app/api/farm/route.ts")], stack: stack(), tables: ["farm", "farmer", "claim"], archive: demo })).toBe("absent");
  });

  it("is unknown when the read was truncated", () => {
    expect(appSignIn({ routes: [], stack: stack(), tables: [], archive: { ...demo, truncated: true } })).toBe("unknown");
  });

  it.each([
    ["an auth provider", { stack: stack([{ id: "clerk", kind: "auth" }]) }],
    ["a route that resolves a user", { routes: [route("/api/farm", "app/api/farm/route.ts", true)] }],
    ["a users table", { tables: ["farm", "usuario"] }],
    ["a profiles table", { tables: ["profiles"] }],
    ["a login route", { routes: [route("/api/auth/login", "app/api/auth/login/route.ts")] }],
    ["a sign-up page", { archive: read({ ...Object.fromEntries(demo.files.map((f) => [f.path, f.content])), "app/signup/page.tsx": "x" }) }],
    ["password hashing", { archive: read({ "lib/a.ts": "import bcrypt from 'bcryptjs'" }) }],
    ["a session cookie read", { archive: read({ "lib/a.ts": "const s = (await cookies()).get('crm_session')" }) }],
    ["a password column", { archive: read({ "prisma/schema.prisma": "model Owner {\n  password String\n}" }) }],
    ["a client-held user id", { archive: read({ "components/login.tsx": "localStorage.setItem('userId', id)" }) }],
  ])("is present with %s", (_name, override) => {
    expect(appSignIn({ routes: [route("/api/farm", "app/api/farm/route.ts")], stack: stack(), tables: ["farm"], archive: demo,
      ...override })).toBe("present");
  });

  it("does not take a theme cookie for a session", () => {
    expect(appSignIn({ routes: [], stack: stack(), tables: [], archive: read({ "lib/a.ts": "cookies().get('theme')" }) })).toBe("absent");
  });
});

// The census (attempts 3 to 5, labeled): apps with no sign-in held 31 true
// findings and 5 false, so absence alone is not the signal. The false ones
// were apps whose own code says they are open by design.
describe("openByDesign", () => {
  const none = { routes: [], stack: stack(), tables: [] };
  it("names a hard-coded demo identity in an app with no sign-in", () => {
    expect(openByDesign({ ...none, archive: read({ "src/lib/demo.ts": "// demo\nexport const DEMO_FARMER_ID = 'f1';" }) }))
      .toEqual({ file: "src/lib/demo.ts", line: 2, reason: "sets a fixed demo identity (DEMO_FARMER_ID)" });
  });
  it("names an author's statement that the app has no sign-in", () => {
    expect(openByDesign({ ...none, archive: read({ "src/lib/saved.ts": " * There is no auth in this app, so saved cases are per browser" }) }))
      .toEqual({ file: "src/lib/saved.ts", line: 1, reason: "says there is no sign-in in this app" });
  });
  it("is null when the app signs people in, even with a demo identity", () => {
    expect(openByDesign({ ...none, stack: stack([{ id: "clerk", kind: "auth" }]),
      archive: read({ "src/lib/demo.ts": "export const DEMO_USER_ID = 'u';" }) })).toBeNull();
  });
  it("is null for demo data, self-hosting or an environment template alone", () => {
    expect(openByDesign({ ...none, archive: read({ "a.ts": "// demo data, self-hosted", ".env.example": "DEMO_FARMER_ID=" }) })).toBeNull();
  });
  it("is null when the read was truncated", () => {
    expect(openByDesign({ ...none, archive: { ...read({ "d.ts": "export const DEMO_USER_ID = 'u';" }), truncated: true } })).toBeNull();
  });
});
