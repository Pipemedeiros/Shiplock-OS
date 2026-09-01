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

// Named for the run that found it: six credential classes on ShipLock's own
// dashboard, every one a fixture inside this file's own test suite, added by
// the commit that created historyScan.ts.
describe("the history scanner reporting its own test data", () => {
  const commit = (patch: string) => ({
    sha: "d93adcea9be5bceff20d86a98d91751f81fc3fe7",
    message: "feat: secrets in history",
    date: new Date().toISOString(),
    patch,
  });

  it("stays silent on a synthetic key added to a test file", () => {
    const hits = scanPatches([
      commit(
        `diff --git a/lib/deep/historyScan.test.ts b/lib/deep/historyScan.test.ts\n` +
          `+  const patch = "sk_live_example_key_0000000000";\n`
      ),
    ]);
    expect(hits).toEqual([]);
  });

  it("stays silent on a vendor's published example inside a comment", () => {
    const hits = scanPatches([
      commit(
        `diff --git a/lib/deep/githubScan.ts b/lib/deep/githubScan.ts\n` +
          `+      // AKIAIOSFODNN7EXAMPLE is Amazon's own published example key\n`
      ),
    ]);
    expect(hits).toEqual([]);
  });

  it("STILL reports a real-looking key added to a test file", () => {
    // The rule is not "skip test files". A suite that talks to a live sandbox
    // needs a real key, and silence there is the failure Coverage exists for.
    const hits = scanPatches([
      commit(
        `diff --git a/lib/x.test.ts b/lib/x.test.ts\n` +
          `+  const key = "sb_secret_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5";\n`
      ),
    ]);
    expect(hits.map((h) => h.secretId)).toEqual(["supabase_secret"]);
  });

  it("STILL reports a real key added to shipped code", () => {
    const hits = scanPatches([
      commit(
        `diff --git a/lib/config.ts b/lib/config.ts\n` +
          `+const key = "sk_live_51H8xQ2eZvKYlo2Cabcdefgh";\n`
      ),
    ]);
    expect(hits.map((h) => h.secretId)).toEqual(["stripe_live"]);
  });

  it("attributes a hit to the file it was added to, not the whole commit", () => {
    // One commit touching two files: a synthetic fixture and a real key.
    const hits = scanPatches([
      commit(
        `diff --git a/lib/deep/x.test.ts b/lib/deep/x.test.ts\n` +
          `+  const fake = "sk_live_example_0000000000000";\n` +
          `diff --git a/lib/pay.ts b/lib/pay.ts\n` +
          `+const real = "sk_live_51H8xQ2eZvKYlo2Cabcdefgh";\n`
      ),
    ]);
    expect(hits.map((h) => h.secretId)).toEqual(["stripe_live"]);
  });
});
