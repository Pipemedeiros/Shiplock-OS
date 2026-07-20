import { describe, expect, it } from "vitest";
import { classifyExposed, _PROBES } from "./exposedPaths";

const probe = (group: string) => _PROBES.find((p) => p.group === group)!;

describe("classifyExposed — catches real exposures", () => {
  it("flags an exposed .git repo (HEAD signature)", () => {
    const f = classifyExposed(probe("git_exposed"), 200, "ref: refs/heads/main\n");
    expect(f?.id).toBe("exposed:git_exposed");
    expect(f?.severity).toBe("CRITICAL");
  });
  it("flags a served database dump", () => {
    const f = classifyExposed(_PROBES.find((p) => p.path === "/backup.sql")!, 200, "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);");
    expect(f?.id).toBe("exposed:db_dump_exposed");
  });
  it("flags an .npmrc with an auth token", () => {
    const f = classifyExposed(probe("npmrc_exposed"), 200, "//registry.npmjs.org/:_authToken=abc123");
    expect(f?.severity).toBe("WARNING");
  });
  it("flags an exposed private SSH key", () => {
    const f = classifyExposed(probe("ssh_key_exposed"), 200, "-----BEGIN OPENSSH PRIVATE KEY-----\n...");
    expect(f?.id).toBe("exposed:ssh_key_exposed");
  });
});

describe("classifyExposed — no false positives", () => {
  it("ignores a 404", () => {
    expect(classifyExposed(probe("git_exposed"), 404, "ref: refs/heads/main")).toBeNull();
  });
  it("ignores an SPA catch-all serving index.html even on 200 with a stray match", () => {
    const html = "<!DOCTYPE html><html><head><title>App</title></head><body>ref: refs/ something</body></html>";
    expect(classifyExposed(probe("git_exposed"), 200, html)).toBeNull();
  });
  it("ignores a 200 whose body lacks the file's signature", () => {
    expect(classifyExposed(probe("git_exposed"), 200, "not a git file")).toBeNull();
    expect(classifyExposed(_PROBES.find((p) => p.path === "/dump.sql")!, 200, "just some text")).toBeNull();
  });
});
