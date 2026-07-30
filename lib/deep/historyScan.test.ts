import { describe, expect, it } from "vitest";
import { historyFindings, MAX_COMMITS, scanPatches, type CommitPatch } from "./historyScan";

const commit = (patch: string, over: Partial<CommitPatch> = {}): CommitPatch => ({
  sha: "abc123def456789",
  message: "wip",
  patch,
  date: new Date(Date.now() - 3 * 86_400_000).toISOString(),
  ...over,
});

describe("scanPatches", () => {
  it("finds a credential in an added line", () => {
    const hits = scanPatches([commit('+const key = "sk_live_51Habcdefghijklmnop";')]);
    expect(hits).toHaveLength(1);
    expect(hits[0].secretId).toBe("stripe_live");
  });

  // THE critical behaviour: a diff contains both sides, so scanning the whole
  // patch would flag the commit that REMOVED the secret — reporting the fix as
  // the problem, at the moment the developer did the right thing.
  it("does NOT flag the commit that removed a secret", () => {
    expect(scanPatches([commit('-const key = "sk_live_51Habcdefghijklmnop";')])).toEqual([]);
  });

  it("ignores the +++ file header", () => {
    expect(scanPatches([commit("+++ b/sk_live_51Habcdefghijklmnop.txt")])).toEqual([]);
  });

  it("recognises each credential class", () => {
    const cases: [string, string][] = [
      ['+sb_secret_AbCdEfGhIjKlMnOp', "supabase_secret"],
      ["+AKIAIOSFODNN7EXAMPLE", "aws_key"],
      ["+sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv", "anthropic"],
      ["+ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01", "github_token"],
      ["+-----BEGIN RSA PRIVATE KEY-----", "private_key"],
      ["+xoxb-1234567890-abcdefghij", "slack_token"],
    ];
    for (const [line, id] of cases) {
      expect(scanPatches([commit(line)])[0]?.secretId, line).toBe(id);
    }
  });

  it("reports one finding per secret class, not per commit", () => {
    const hits = scanPatches([
      commit('+key = "sk_live_51Habcdefghijklmnop"', { sha: "aaa" }),
      commit('+key = "sk_live_51Habcdefghijklmnop"', { sha: "bbb" }),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0].sha).toBe("aaa");
  });

  it("is silent on an ordinary diff", () => {
    expect(scanPatches([commit("+const timeout = 30;\n-const timeout = 10;")])).toEqual([]);
  });

  // Reading history costs an API call per commit.
  it("stops at the commit cap", () => {
    const many = Array.from({ length: MAX_COMMITS + 50 }, (_, i) =>
      commit(i === MAX_COMMITS + 10 ? '+sk_live_51Habcdefghijklmnop' : "+ok", { sha: `c${i}` })
    );
    expect(scanPatches(many)).toEqual([]);
  });

  it("handles an empty list", () => {
    expect(scanPatches([])).toEqual([]);
  });
});

describe("historyFindings", () => {
  const hits = scanPatches([commit('+key = "sk_live_51Habcdefghijklmnop"')]);

  it("is CRITICAL on a public repo and says bots index it", () => {
    const out = historyFindings(hits, true);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].consequence).toContain("index public commits within minutes");
  });

  it("is WARNING on a private repo but names who still has it", () => {
    const out = historyFindings(hits, false);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("every past collaborator");
  });

  // The whole point of the finding.
  it("says rotation is the only action that helps", () => {
    expect(historyFindings(hits, true)[0].consequence).toContain("ONLY ACTION THAT HELPS IS ROTATING");
  });

  it("warns that rewriting history does not reliably help", () => {
    expect(historyFindings(hits, true)[0].consequence).toContain("orphaned commits");
  });

  // A fix PR would be actively misleading: the code is already correct.
  it("explains why there is no pull request for this", () => {
    expect(historyFindings(hits, true)[0].consequence).toContain("nothing to change in your code");
  });

  it("says how long ago it happened", () => {
    expect(historyFindings(hits, true)[0].title).toContain("3 days ago");
  });

  // Already reported by the committed-secrets check.
  it("does not repeat a secret that is STILL in the working tree", () => {
    expect(historyFindings(hits, true, new Set(["stripe_live"]))).toEqual([]);
  });

  it("handles no hits", () => {
    expect(historyFindings([], true)).toEqual([]);
  });

  it("produces stable ids", () => {
    expect(historyFindings(hits, true).map((x) => x.id)).toEqual(historyFindings(hits, true).map((x) => x.id));
  });
});
