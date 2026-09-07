import { describe, expect, it } from "vitest";
import { jwtRole, resolveImport, stripComments } from "./clientExposure";
import type { RepoFile } from "./githubScan";

const file = (path: string, content: string): RepoFile => ({ path, content });

// A legacy Supabase JWT is `header.payload.signature`, base64url, unsigned here
// (we only ever decode the payload — we never verify these).
const jwt = (role: string) => {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role })}.c2ln`;
};

describe("stripComments — documentation must never be a finding", () => {
  it("removes line comments", () => {
    expect(stripComments("const a = 1; // SUPABASE_SERVICE_ROLE_KEY")).not.toContain("SERVICE_ROLE");
  });

  it("removes block comments, including multi-line ones", () => {
    expect(stripComments("/*\n * never use SERVICE_ROLE_KEY here\n */\nconst a = 1;")).not.toContain("SERVICE_ROLE");
  });

  it("keeps the code that surrounds a comment", () => {
    expect(stripComments("const a = 1; // note\nconst b = 2;")).toContain("const b = 2");
  });

  it("does not eat the // in a URL string literal", () => {
    expect(stripComments('fetch("https://api.example.com/x");')).toContain("api.example.com");
  });
});

describe("resolveImport", () => {
  const byPath = new Map<string, RepoFile>([
    ["lib/a.ts", file("lib/a.ts", "")],
    ["src/lib/b.ts", file("src/lib/b.ts", "")],
    ["lib/c/index.tsx", file("lib/c/index.tsx", "")],
  ]);

  it("resolves an @/ alias", () => {
    expect(resolveImport("app/p.tsx", "@/lib/a", byPath)).toBe("lib/a.ts");
  });

  it("falls back to a src/ prefix when the project uses one", () => {
    expect(resolveImport("app/p.tsx", "@/lib/b", byPath)).toBe("src/lib/b.ts");
  });

  it("resolves a directory to its index", () => {
    expect(resolveImport("app/p.tsx", "@/lib/c", byPath)).toBe("lib/c/index.tsx");
  });

  it("resolves a relative path with .. segments", () => {
    expect(resolveImport("app/x/y/p.tsx", "../../../lib/a", byPath)).toBe("lib/a.ts");
  });

  it("returns null for a bare package specifier", () => {
    expect(resolveImport("app/p.tsx", "@supabase/supabase-js", byPath)).toBeNull();
    expect(resolveImport("app/p.tsx", "react", byPath)).toBeNull();
  });

  it("returns null for a local path that isn't in the file set", () => {
    expect(resolveImport("app/p.tsx", "./nope", byPath)).toBeNull();
  });
});

describe("jwtRole", () => {
  it("decodes the anon role", () => {
    expect(jwtRole(jwt("anon"))).toBe("anon");
  });

  it("decodes the service_role role", () => {
    expect(jwtRole(jwt("service_role"))).toBe("service_role");
  });

  it("returns null for a non-JWT string", () => {
    expect(jwtRole("sb_publishable_abc123")).toBeNull();
  });

  it("returns null for a JWT-shaped string with an undecodable payload", () => {
    expect(jwtRole("eyJhbGciOi.eyJub3RqLXNvbg.sig")).toBeNull();
  });

  it("returns null when the payload has no role claim", () => {
    expect(jwtRole(jwt(undefined as unknown as string))).toBeNull();
  });
});
