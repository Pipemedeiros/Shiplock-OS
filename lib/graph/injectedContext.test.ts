import { describe, expect, it } from "vitest";
import { analyzeRouteFile } from "./routeInventory";

// Class C (P1, Q26 dev labels): a wrapper resolves the session and the
// caller's workspace membership, then hands the handler the membership's own
// workspace id. A filter on that id scopes to the caller's tenant. The shape
// corpus-a uses (`({ workspace }) =>`, first parameter) was already read; these are
// the shapes it missed. Credited only when the wrapper also reads a membership
// table, because an id the wrapper took from the request is not the caller's.
const fact = (route: string, wrapper: string) => {
  const files = { "lib/rls.ts": wrapper, "app/api/accounts/route.ts": route };
  const byPath = new Map(Object.entries(files).map(([path, content]) => [path, { path, content }]));
  return analyzeRouteFile("app/api/accounts/route.ts", route, byPath);
};

const membershipWrapper = `export function withRLSContext(handler) {
  return async (request) => {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "x" }, { status: 401 });
    const { data } = await supabase.from("workspace_members").select("workspace_id").eq("user_id", user.id).single();
    if (!data) return NextResponse.json({ error: "x" }, { status: 403 });
    return handler(request, { supabase, workspaceId: data.workspace_id, userId: user.id });
  };
}`;
const headerWrapper = `export function withRLSContext(handler) {
  return async (request) => {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return NextResponse.json({ error: "x" }, { status: 401 });
    return handler(request, { supabase, workspaceId: request.headers.get("x-workspace") });
  };
}`;
const noIdentityWrapper = `export function withRLSContext(handler) {
  return async (request) => {
    const { data } = await supabase.from("workspace_members").select("workspace_id").limit(1).single();
    return handler(request, { supabase, workspaceId: data.workspace_id });
  };
}`;

const namedHandler = `import { withRLSContext } from "@/lib/rls";
async function handleList(request, context) {
  const { supabase, workspaceId } = context;
  const { data } = await supabase.from("accounts").select("*").eq("workspace_id", workspaceId);
  return NextResponse.json(data);
}
export const GET = withRLSContext(handleList);`;
const inlineSecond = `import { withRLSContext } from "@/lib/rls";
export const GET = withRLSContext(async (request, { supabase, workspaceId }) => {
  const { data } = await supabase.from("accounts").select("*").eq("workspace_id", workspaceId);
  return NextResponse.json(data);
});`;

describe("a workspace a membership wrapper established", () => {
  it("scopes a named handler that destructures the context in its body", () => {
    expect(fact(namedHandler, membershipWrapper)).toMatchObject({ authenticated: true, ownershipFiltered: true });
  });

  it("scopes an inline handler that takes the context as its second parameter", () => {
    expect(fact(inlineSecond, membershipWrapper)).toMatchObject({ authenticated: true, ownershipFiltered: true });
  });

  it("does not scope when the wrapper took the workspace from the request", () => {
    expect(fact(namedHandler, headerWrapper).ownershipFiltered).toBe(false);
    expect(fact(inlineSecond, headerWrapper).ownershipFiltered).toBe(false);
  });

  it("does not scope when the wrapper resolves no caller", () => {
    expect(fact(namedHandler, noIdentityWrapper).ownershipFiltered).toBe(false);
  });

  it("does not scope a filter on something other than the established workspace", () => {
    const route = namedHandler.replace(`.eq("workspace_id", workspaceId)`, `.eq("workspace_id", new URL(request.url).searchParams.get("w"))`);
    expect(fact(route, membershipWrapper).ownershipFiltered).toBe(false);
  });

  it("does not scope a query that ignores the established workspace", () => {
    const route = namedHandler.replace(`.eq("workspace_id", workspaceId)`, ``);
    expect(fact(route, membershipWrapper).ownershipFiltered).toBe(false);
  });
});
