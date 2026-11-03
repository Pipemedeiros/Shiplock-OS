import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { checkRule, FIXTURES, matches, registrySchema, syntaxDigest, type CommitEvidence, type Snapshot } from "./repoGuardrails";

const expectedIds = ["markdown-files", "model-clients", "model-keys", "client-server-boundary", "receipted-pr-writes", "cookie-origin", "nonce-csp", "dynamic-layout", "customer-copy", "crawler-agreement", "tracked-secrets", "migration-sequence", "migration-loads", "provider-writes", "agents-approval"];
const registry = registrySchema.parse(JSON.parse(readFileSync(".agents/guardrails.json", "utf8")));
const tracked = execFileSync("git", ["ls-files", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean);
const files: Snapshot = new Map(tracked.filter(p => !p.startsWith(FIXTURES)).map(p => {
  try { return [p, readFileSync(p, "utf8")]; } catch { return [p, ""]; } // Deletions remain visible to pins.
}));
const pathSchema = z.string().min(1).refine(p => !p.startsWith("/") && !p.split("/").includes("..") && !p.startsWith(FIXTURES));
const fixtureSchema = z.object({
  rule: z.string(),
  cases: z.array(z.object({
    name: z.string().min(1), expectedPath: pathSchema,
    edits: z.array(z.union([
      z.object({ path: pathSchema, content: z.string() }).strict(),
      z.object({ path: pathSchema, remove: z.literal(true) }).strict(),
      z.object({ path: pathSchema, commentAll: z.literal(true) }).strict(),
      z.object({ path: pathSchema, replace: z.object({ from: z.string().min(1), to: z.string() }).strict() }).strict(),
    ])),
    commits: z.array(z.object({ changedPaths: z.array(pathSchema), message: z.string() }).strict()).optional(),
  }).strict()).min(1),
}).strict();

function commitEvidence(): CommitEvidence[] {
  const message = execFileSync("git", ["log", "-1", "--format=%B", "--", "AGENTS.md"], { encoding: "utf8" });
  const pending = execFileSync("git", ["diff", "--name-only", "HEAD", "--", "AGENTS.md"], { encoding: "utf8" }).trim();
  return [{ changedPaths: ["AGENTS.md"], message }, ...(pending ? [{ changedPaths: ["AGENTS.md"], message: "Pending commit: approval message not yet available" }] : [])];
}
const commits = commitEvidence();

describe("repository guardrail integrity", () => {
  it("the guardrail file has a versioned registry and a violating fixture for every rule", () => {
    expect(registry.rules.map(r => r.id).sort()).toEqual([...expectedIds].sort());
    expect(tracked).toContain(".agents/guardrails.json");
    expect(tracked).toContain("lib/security/repoGuardrails.test.ts");
    for (const rule of registry.rules) {
      expect(rule.enforcedBy).toEqual({ file: "lib/security/repoGuardrails.test.ts", test: `enforces ${rule.id}` });
      expect(tracked).toContain(`${FIXTURES}${rule.id}.json`);
      const fixture = fixtureSchema.parse(JSON.parse(readFileSync(`${FIXTURES}${rule.id}.json`, "utf8")));
      expect(fixture.rule).toBe(rule.id);
      expect(fixture.cases.length).toBeGreaterThan(0);
    }
  });
  it("rejects missing metadata, unknown checks, duplicate ids and unversioned registries", () => {
    expect(registrySchema.safeParse({ ...registry, version: 2 }).success).toBe(false);
    expect(registrySchema.safeParse({ ...registry, rules: [...registry.rules, registry.rules[0]] }).success).toBe(false);
    expect(registrySchema.safeParse({ ...registry, rules: [{ ...registry.rules[0], why: "" }, ...registry.rules.slice(1)] }).success).toBe(false);
    expect(registrySchema.safeParse({ ...registry, rules: [{ ...registry.rules[0], check: "pretend" }, ...registry.rules.slice(1)] }).success).toBe(false);
  });
  it("normalizes comments without allowing commented assertions to satisfy pins", () => {
    expect(syntaxDigest("a.ts", "expect(x).toBe(false);")).toBe(syntaxDigest("a.ts", "// marker\nexpect(x).toBe(false);"));
    expect(syntaxDigest("a.ts", "// expect(x).toBe(false);")).not.toBe(syntaxDigest("a.ts", "expect(x).toBe(false);"));
  });
  it("matches only anchored repository globs including dot paths", () => {
    expect(matches(".agents/skills/a/b.md", ".agents/skills/**")).toBe(true);
    expect(matches("lib/a.ts", "**/*.ts")).toBe(true);
    expect(matches("proxy.ts", "**/*.ts")).toBe(true);
    expect(matches("other/AGENTS.md", "AGENTS.md")).toBe(false);
  });
});

for (const rule of registry.rules) {
  it(`enforces ${rule.id}`, () => {
    const violations = checkRule(rule, files, commits);
    if (rule.severity === "warn") {
      for (const v of violations) console.warn(`${v.rule}: ${v.path}: ${v.reason}`);
    } else expect(violations).toEqual([]);
  });
  const fixture = fixtureSchema.parse(JSON.parse(readFileSync(`${FIXTURES}${rule.id}.json`, "utf8")));
  for (const example of fixture.cases) {
    it(`rejects ${rule.id}: ${example.name}`, () => {
      const mutated = new Map(files);
      for (const edit of example.edits) {
        if ("content" in edit) mutated.set(edit.path, edit.content);
        else if ("remove" in edit) mutated.delete(edit.path);
        else if ("commentAll" in edit) {
          expect(mutated.has(edit.path)).toBe(true);
          mutated.set(edit.path, mutated.get(edit.path)!.split("\n").map(line => `// ${line}`).join("\n"));
        } else {
          const before = mutated.get(edit.path);
          expect(before, `Fixture target ${edit.path} missing`).toBeDefined();
          expect(before, `Fixture mutation no longer matches ${edit.path}`).toContain(edit.replace.from);
          mutated.set(edit.path, before!.replace(edit.replace.from, edit.replace.to));
        }
      }
      const violations = checkRule(rule, mutated, example.commits ?? []);
      expect(violations.some(v => v.rule === rule.id && v.path === example.expectedPath), JSON.stringify(violations)).toBe(true);
    });
  }
}
