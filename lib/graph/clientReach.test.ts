import { describe, expect, it } from "vitest";
import { reachFromCode, withReach } from "./clientReach";

const f = (path: string, content: string) => ({ path, content });

describe("reachFromCode: is an entry called by the app's own pages or components", () => {
  it("finds a route handler called by a component, with the dynamic segment filled in", () => {
    const files = [
      f("app/api/notes/[id]/route.ts", "export async function GET() {}"),
      f("components/Note.tsx", "\"use client\"; fetch(`/api/notes/${id}`)"),
    ];
    expect(reachFromCode({ path: "/api/notes/[id]", file: "app/api/notes/[id]/route.ts" }, files))
      .toEqual({ reached: true, by: ["components/Note.tsx"] });
  });

  it("matches a static route only as a whole path, not as a prefix of a longer one", () => {
    const files = [
      f("app/api/notes/route.ts", ""),
      f("components/List.tsx", "fetch('/api/notes/archive')"),
    ];
    expect(reachFromCode({ path: "/api/notes", file: "app/api/notes/route.ts" }, files).reached).toBe(false);
    files.push(f("components/All.tsx", "fetch(\"/api/notes?page=2\")"));
    expect(reachFromCode({ path: "/api/notes", file: "app/api/notes/route.ts" }, files).by).toEqual(["components/All.tsx"]);
  });

  it("does not count the route's own file, tests or server-only helpers as reach", () => {
    const files = [
      f("app/api/admin/route.ts", "const self = '/api/admin';"),
      f("tests/admin.test.ts", "fetch('/api/admin')"),
      f("e2e/admin.spec.ts", "fetch('/api/admin')"),
    ];
    expect(reachFromCode({ path: "/api/admin", file: "app/api/admin/route.ts" }, files).reached).toBe(false);
  });

  it("finds a tRPC procedure called from a client hook, through nested routers", () => {
    const files = [
      f("server/routers/users.ts", "getMany: publicProcedure.query(() => db.select())"),
      f("app/users/page.tsx", "const q = trpc.users.getMany.useQuery({ page: 1 });"),
    ];
    expect(reachFromCode({ path: "trpc:server/routers/users.ts#getMany", file: "server/routers/users.ts" }, files))
      .toEqual({ reached: true, by: ["app/users/page.tsx"] });
  });

  it("uses the importers already recorded for a server action", () => {
    const action = { path: "action:app/actions.ts#deleteNote", file: "app/actions.ts" };
    expect(reachFromCode({ ...action, via: ["components/DeleteButton.tsx"] }, []).by).toEqual(["components/DeleteButton.tsx"]);
    expect(reachFromCode({ ...action, via: [] }, []).reached).toBe(false);
  });

  it("strips an app-root prefix from a duplicated route path", () => {
    const files = [f("apps/web/components/A.tsx", "fetch('/api/ping')")];
    expect(reachFromCode({ path: "apps/web:/api/ping", file: "apps/web/app/api/ping/route.ts" }, files).reached).toBe(true);
  });

  it("annotates every route from one index", () => {
    const files = [f("components/A.tsx", "fetch('/api/a'); fetch(`/api/b/${id}`)")];
    const routes = withReach([{ path: "/api/a", file: "app/api/a/route.ts" }, { path: "/api/b/[id]", file: "x" }, { path: "/api/c", file: "y" }], files);
    expect(routes.map((r) => r.calledBy)).toEqual([["components/A.tsx"], ["components/A.tsx"], []]);
  });
});
