import { describe, expect, it } from "vitest";
import { checkRepoVisibility, isSecretFinding } from "./repoVisibility";
import type { GithubFinding } from "./githubScan";

const f = (id: string, title = "t"): GithubFinding => ({
  id,
  severity: "CRITICAL",
  title,
  consequence: "c",
  packageName: null,
  version: null,
  vulnId: null,
  cveId: null,
});

const repo = (over: Partial<Parameters<typeof checkRepoVisibility>[0]> = {}) => ({
  fullName: "acme/app",
  isPrivate: false,
  visibility: "public",
  ...over,
});

describe("isSecretFinding", () => {
  it("recognises every finding class that means a credential is in the repo", () => {
    for (const id of [
      "github:secret:private_key:a.pem",
      "github:committed_env:.env",
      "github:client_server_secret:app/p.tsx",
      "github:public_prefixed_secret:NEXT_PUBLIC_X_SECRET:.env",
      "github:public_prefixed_secret_value:NEXT_PUBLIC_X:.env",
    ]) {
      expect(isSecretFinding(id), id).toBe(true);
    }
  });

  it("does not treat non-credential findings as secrets", () => {
    for (const id of [
      "github:xss_sink:inner_html_assign:a.tsx",
      "github:dep:lodash",
      "github:injection:sql_injection:a.ts",
      "advisor:rls_policy_always_true:public.orders",
    ]) {
      expect(isSecretFinding(id), id).toBe(false);
    }
  });
});

describe("checkRepoVisibility — C22", () => {
  it("says nothing about a private repo", () => {
    expect(checkRepoVisibility(repo({ isPrivate: true, visibility: "private" }), [])).toEqual([]);
  });

  // A missing field is not evidence of a public repo. Unknown must never alarm.
  it("says nothing when GitHub didn't report visibility", () => {
    expect(checkRepoVisibility(repo({ isPrivate: null, visibility: null }), [])).toEqual([]);
  });

  it("says nothing about an enterprise 'internal' repo — org members, not the world", () => {
    expect(checkRepoVisibility(repo({ visibility: "internal" }), [])).toEqual([]);
  });

  // Open-sourcing on purpose is normal. The tone has to respect that.
  it("reports a public repo with no secrets as a WARNING, and says it may be deliberate", () => {
    const out = checkRepoVisibility(repo(), []);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].id).toBe("github:repo_public:acme/app");
    expect(out[0].consequence).toContain("If that's deliberate");
  });

  it("explains that history keeps a deleted secret readable", () => {
    expect(checkRepoVisibility(repo(), [])[0].consequence).toContain("does not remove it from history");
  });

  it("does not escalate on non-credential findings", () => {
    const out = checkRepoVisibility(repo(), [f("github:xss_sink:eval_call:a.tsx")]);
    expect(out[0].severity).toBe("WARNING");
  });

  // The correlation this check exists for: neither fact alarms alone.
  it("escalates to CRITICAL when the public repo also contains credentials", () => {
    const out = checkRepoVisibility(repo(), [
      f("github:committed_env:.env", "Environment file committed to the repo (.env)"),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].id).toBe("github:repo_public_with_secrets:acme/app");
  });

  it("counts and names each leaked credential so the finding is actionable", () => {
    const out = checkRepoVisibility(repo(), [
      f("github:committed_env:.env", "env committed"),
      f("github:secret:aws_access_key:x.ts", "aws key committed"),
    ]);
    expect(out[0].title).toContain("2 exposed credentials");
    expect(out[0].consequence).toContain("env committed");
    expect(out[0].consequence).toContain("aws key committed");
  });

  it("singularises a single credential", () => {
    expect(checkRepoVisibility(repo(), [f("github:committed_env:.env")])[0].title).toContain("1 exposed credential");
  });

  // Rotation is the only step that works, and the ordering matters — the two
  // instinctive reactions (delete the file, flip the repo private) both fail.
  it("orders the fix as rotate-first and rules out the two useless reactions", () => {
    const { consequence } = checkRepoVisibility(repo(), [f("github:committed_env:.env")])[0];
    expect(consequence).toContain("ROTATE them now");
    expect(consequence).toContain("Deleting the files does not help");
    expect(consequence).toContain("Making the repository private also does not help");
    expect(consequence).toContain("already compromised");
  });

  it("uses per-repo ids so two public repos are two findings", () => {
    const a = checkRepoVisibility(repo({ fullName: "acme/api" }), []);
    const b = checkRepoVisibility(repo({ fullName: "acme/web" }), []);
    expect(a[0].id).not.toBe(b[0].id);
  });

  it("returns findings in the shared GithubFinding shape", () => {
    for (const finding of checkRepoVisibility(repo(), [])) {
      expect(finding.packageName).toBeNull();
      expect(finding.version).toBeNull();
      expect(finding.vulnId).toBeNull();
      expect(finding.cveId).toBeNull();
    }
  });
});
