import { describe, expect, it, vi } from "vitest";
import {
  isAbsenceError,
  nodeTxtResolver,
  analyzeDkim,
  analyzeDmarc,
  analyzeSpf,
  auditEmailAuth,
  DKIM_SELECTORS,
  domainFromUrl,
  isSharedHost,
} from "./emailAuth";

const D = "example.com";

describe("domainFromUrl", () => {
  it("takes the hostname from a URL", () => {
    expect(domainFromUrl("https://example.com/dashboard")).toBe("example.com");
  });

  it("strips www, which never has its own email auth", () => {
    expect(domainFromUrl("https://www.example.com")).toBe("example.com");
  });

  it("lowercases the host", () => {
    expect(domainFromUrl("https://Example.COM")).toBe("example.com");
  });

  it("keeps a subdomain that isn't www", () => {
    expect(domainFromUrl("https://app.example.com")).toBe("app.example.com");
  });

  it("rejects localhost and bare IPs, which have no email auth to check", () => {
    expect(domainFromUrl("http://localhost:3000")).toBeNull();
    expect(domainFromUrl("http://127.0.0.1")).toBeNull();
  });

  it("rejects an unparseable URL", () => {
    expect(domainFromUrl("not a url")).toBeNull();
  });
});

describe("isSharedHost", () => {
  // The customer can't edit DNS they don't own, so a finding there is noise.
  it("recognises platform domains the customer does not control", () => {
    for (const host of [
      "myapp.vercel.app",
      "myapp.netlify.app",
      "myapp.pages.dev",
      "myapp.fly.dev",
      "myapp.onrender.com",
      "myapp.up.railway.app",
      "abc.supabase.co",
      "me.github.io",
      "x.workers.dev",
      "x.replit.app",
    ]) {
      expect(isSharedHost(host), host).toBe(true);
    }
  });

  it("does not treat a real customer domain as shared", () => {
    expect(isSharedHost("example.com")).toBe(false);
    expect(isSharedHost("shiplock.dev")).toBe(false);
  });

  it("is not fooled by a domain that merely contains a platform name", () => {
    expect(isSharedHost("vercel.app.example.com")).toBe(false);
    expect(isSharedHost("notvercel.app")).toBe(false);
  });
});

describe("analyzeSpf", () => {
  it("flags a domain with no SPF record", () => {
    const out = analyzeSpf(D, []);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("email_auth:spf_missing");
    expect(out[0].consequence).toContain("password-reset");
  });

  it("ignores unrelated TXT records when deciding SPF is missing", () => {
    expect(analyzeSpf(D, ["google-site-verification=abc", "MS=ms12345"])[0].id).toBe("email_auth:spf_missing");
  });

  it("accepts a healthy record ending in ~all", () => {
    expect(analyzeSpf(D, ["v=spf1 include:_spf.google.com ~all"])).toEqual([]);
  });

  it("accepts a healthy record ending in -all", () => {
    expect(analyzeSpf(D, ["v=spf1 include:amazonses.com -all"])).toEqual([]);
  });

  it("is case-insensitive about the version tag", () => {
    expect(analyzeSpf(D, ["v=SPF1 include:_spf.google.com ~all"])).toEqual([]);
  });

  it("tolerates surrounding whitespace", () => {
    expect(analyzeSpf(D, ["  v=spf1 include:_spf.google.com ~all  "])).toEqual([]);
  });

  // +all is worse than nothing: it actively vouches for every sender.
  it("treats +all as CRITICAL", () => {
    const out = analyzeSpf(D, ["v=spf1 +all"]);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].id).toBe("email_auth:spf_pass_all");
  });

  it("treats a bare trailing all (which means +all) as CRITICAL", () => {
    expect(analyzeSpf(D, ["v=spf1 include:_spf.google.com all"])[0].severity).toBe("CRITICAL");
  });

  it("flags a neutral ?all as enforcing nothing", () => {
    expect(analyzeSpf(D, ["v=spf1 include:x.com ?all"])[0].id).toBe("email_auth:spf_neutral_all");
  });

  it("flags a record with no all mechanism at all", () => {
    expect(analyzeSpf(D, ["v=spf1 include:_spf.google.com"])[0].id).toBe("email_auth:spf_no_all");
  });

  // Two records is a permerror: receivers discard both, so a domain that looks
  // doubly protected is actually unprotected.
  it("flags multiple SPF records, and says why that means zero protection", () => {
    const out = analyzeSpf(D, ["v=spf1 include:a.com ~all", "v=spf1 include:b.com ~all"]);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("email_auth:spf_multiple");
    expect(out[0].consequence).toContain("discard");
  });

  it("flags a record over the 10-lookup limit", () => {
    const record = `v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:p${i}.com`).join(" ")} ~all`;
    const out = analyzeSpf(D, [record]);
    expect(out.some((f) => f.id === "email_auth:spf_too_many_lookups")).toBe(true);
  });

  it("does not flag lookups when the record is within the limit", () => {
    const record = `v=spf1 ${Array.from({ length: 9 }, (_, i) => `include:p${i}.com`).join(" ")} ~all`;
    expect(analyzeSpf(D, [record])).toEqual([]);
  });

  it("can report both a bad all mechanism and too many lookups", () => {
    const record = `v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:p${i}.com`).join(" ")} ?all`;
    expect(analyzeSpf(D, [record])).toHaveLength(2);
  });
});

describe("analyzeDmarc", () => {
  it("flags a missing DMARC record", () => {
    const out = analyzeDmarc(D, []);
    expect(out[0].id).toBe("email_auth:dmarc_missing");
    expect(out[0].consequence).toContain("_dmarc.example.com");
  });

  it("accepts p=quarantine as enforcing", () => {
    expect(analyzeDmarc(D, ["v=DMARC1; p=quarantine; rua=mailto:a@example.com"])).toEqual([]);
  });

  it("accepts p=reject as enforcing", () => {
    expect(analyzeDmarc(D, ["v=DMARC1; p=reject"])).toEqual([]);
  });

  // p=none is the right starting point, so the wording must not scold — but it
  // genuinely blocks nothing, so it can't be silence either.
  it("flags p=none as monitoring without protection", () => {
    const out = analyzeDmarc(D, ["v=DMARC1; p=none; rua=mailto:a@example.com"]);
    expect(out[0].id).toBe("email_auth:dmarc_policy_none");
    expect(out[0].consequence).toContain("correct place to START");
  });

  it("flags a record with no p= tag as invalid", () => {
    expect(analyzeDmarc(D, ["v=DMARC1; rua=mailto:a@example.com"])[0].id).toBe("email_auth:dmarc_no_policy");
  });

  it("is case-insensitive about the version and policy", () => {
    expect(analyzeDmarc(D, ["v=dmarc1; P=REJECT"])).toEqual([]);
  });

  it("tolerates spaces around the policy value", () => {
    expect(analyzeDmarc(D, ["v=DMARC1; p = reject"])).toEqual([]);
  });

  it("ignores unrelated TXT records at the _dmarc name", () => {
    expect(analyzeDmarc(D, ["some-other-record"])[0].id).toBe("email_auth:dmarc_missing");
  });
});

describe("analyzeDkim", () => {
  const key2048 = "A".repeat(392);
  const key1024 = "A".repeat(216);

  it("accepts a healthy 2048-bit key", () => {
    expect(analyzeDkim(D, "resend", [`v=DKIM1; k=rsa; p=${key2048}`])).toEqual([]);
  });

  it("accepts a 1024-bit key as adequate, if not ideal", () => {
    expect(analyzeDkim(D, "google", [`v=DKIM1; k=rsa; p=${key1024}`])).toEqual([]);
  });

  it("flags an empty p= value as a revoked key", () => {
    const out = analyzeDkim(D, "resend", ["v=DKIM1; k=rsa; p="]);
    expect(out[0].id).toBe("email_auth:dkim_revoked:resend");
    expect(out[0].consequence).toContain("resend._domainkey.example.com");
  });

  it("flags a key that is too short to be safe", () => {
    const out = analyzeDkim(D, "s1", [`v=DKIM1; k=rsa; p=${"A".repeat(100)}`]);
    expect(out[0].id).toBe("email_auth:dkim_weak_key:s1");
    expect(out[0].consequence).toContain("looks verified");
  });

  // DKIM absence cannot be proven without knowing the selector, so a selector
  // that returns nothing must produce silence — never a "missing DKIM" claim.
  it("says NOTHING when there is no record for the selector", () => {
    expect(analyzeDkim(D, "resend", [])).toEqual([]);
  });

  it("says nothing for a TXT record at the selector that isn't DKIM", () => {
    expect(analyzeDkim(D, "resend", ["unrelated-value"])).toEqual([]);
  });
});

describe("auditEmailAuth — orchestration", () => {
  const clean = (name: string): Promise<string[]> => {
    if (name === "example.com") return Promise.resolve(["v=spf1 include:_spf.google.com ~all"]);
    if (name === "_dmarc.example.com") return Promise.resolve(["v=DMARC1; p=reject"]);
    return Promise.resolve([]);
  };

  it("is silent on a correctly-configured domain", async () => {
    expect(await auditEmailAuth("https://example.com", clean)).toEqual([]);
  });

  it("reports SPF and DMARC problems together", async () => {
    const out = await auditEmailAuth("https://example.com", () => Promise.resolve([]));
    expect(out.map((f) => f.id).sort()).toEqual(["email_auth:dmarc_missing", "email_auth:spf_missing"]);
  });

  // A DNS failure is not evidence of absence. Inventing findings from a timeout
  // is the fastest way to make a monitoring product untrustworthy.
  it("reports NOTHING when DNS fails outright", async () => {
    const out = await auditEmailAuth("https://example.com", () => Promise.reject(new Error("ETIMEOUT")));
    expect(out).toEqual([]);
  });

  it("still reports DMARC when only the SPF lookup fails", async () => {
    const out = await auditEmailAuth("https://example.com", (name) =>
      name === "example.com" ? Promise.reject(new Error("SERVFAIL")) : Promise.resolve([])
    );
    expect(out.map((f) => f.id)).toEqual(["email_auth:dmarc_missing"]);
  });

  it("treats a successful lookup with no TXT records as a genuinely missing record", async () => {
    const out = await auditEmailAuth("https://example.com", () => Promise.resolve([]));
    expect(out.some((f) => f.id === "email_auth:spf_missing")).toBe(true);
  });

  it("skips shared platform domains the customer cannot configure", async () => {
    const resolver = vi.fn().mockResolvedValue([]);
    expect(await auditEmailAuth("https://myapp.vercel.app", resolver)).toEqual([]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it("skips localhost without any DNS traffic", async () => {
    const resolver = vi.fn().mockResolvedValue([]);
    expect(await auditEmailAuth("http://localhost:3000", resolver)).toEqual([]);
    expect(resolver).not.toHaveBeenCalled();
  });

  it("probes every known DKIM selector", async () => {
    const resolver = vi.fn().mockResolvedValue([]);
    await auditEmailAuth("https://example.com", resolver);
    for (const selector of DKIM_SELECTORS) {
      expect(resolver).toHaveBeenCalledWith(`${selector}._domainkey.example.com`);
    }
  });

  it("surfaces a broken DKIM key found at one selector", async () => {
    const out = await auditEmailAuth("https://example.com", (name) => {
      if (name === "resend._domainkey.example.com") return Promise.resolve(["v=DKIM1; k=rsa; p="]);
      return clean(name);
    });
    expect(out.map((f) => f.id)).toEqual(["email_auth:dkim_revoked:resend"]);
  });

  it("produces stable ids so the diff engine can match across passes", async () => {
    const first = await auditEmailAuth("https://example.com", () => Promise.resolve([]));
    const second = await auditEmailAuth("https://example.com", () => Promise.resolve([]));
    expect(first.map((f) => f.id)).toEqual(second.map((f) => f.id));
  });
});

// This is the bug dogfooding found: node's resolveTxt THROWS for a missing
// record instead of returning [], so treating every rejection as "unknown" made
// the whole audit silent for exactly the domains it exists to catch. shiplock.dev
// has neither SPF nor DMARC and initially produced zero findings.
describe("absence vs failure — the distinction the check depends on", () => {
  it("treats ENODATA as proof the record is absent", () => {
    expect(isAbsenceError(Object.assign(new Error("no data"), { code: "ENODATA" }))).toBe(true);
  });

  it("treats ENOTFOUND and NXDOMAIN as proof the name is absent", () => {
    expect(isAbsenceError(Object.assign(new Error("x"), { code: "ENOTFOUND" }))).toBe(true);
    expect(isAbsenceError(Object.assign(new Error("x"), { code: "NXDOMAIN" }))).toBe(true);
  });

  it("does NOT treat a transient failure as absence", () => {
    for (const code of ["SERVFAIL", "ETIMEOUT", "ECONNREFUSED", "EREFUSED"]) {
      expect(isAbsenceError(Object.assign(new Error("x"), { code })), code).toBe(false);
    }
  });

  it("does not treat an error with no code, or a non-error, as absence", () => {
    expect(isAbsenceError(new Error("boom"))).toBe(false);
    expect(isAbsenceError(null)).toBe(false);
    expect(isAbsenceError("ENODATA")).toBe(false);
  });

  it("nodeTxtResolver converts a proven-absent record into an empty array", async () => {
    // A name reserved by RFC 2606 that cannot have records.
    await expect(nodeTxtResolver("_dmarc.invalid")).resolves.toEqual([]);
  });

  it("reports a missing SPF record when the lookup rejects with ENODATA", async () => {
    const resolver = (name: string) =>
      name === "example.com"
        ? Promise.reject(Object.assign(new Error("no data"), { code: "ENODATA" }))
        : Promise.resolve([]);
    // The resolver contract is that absence yields []; this asserts the classifier
    // side stays correct once nodeTxtResolver has done that conversion.
    const converted = (name: string) =>
      resolver(name).catch((err) => {
        if (isAbsenceError(err)) return [] as string[];
        throw err;
      });
    const out = await auditEmailAuth("https://example.com", converted);
    expect(out.map((f) => f.id).sort()).toEqual(["email_auth:dmarc_missing", "email_auth:spf_missing"]);
  });
});

describe("auditEmailAuth — 1E-1 readability", () => {
  it("marks every record family unread when DNS fails outright", async () => {
    const unread: string[] = [];
    await auditEmailAuth("https://example.com", () => Promise.reject(new Error("ETIMEOUT")), unread);
    expect(unread).toEqual(expect.arrayContaining([
      "email_auth:spf_", "email_auth:dmarc_",
      expect.stringMatching(/^email_auth:dkim_revoked:/), expect.stringMatching(/^email_auth:dkim_weak_key:/),
    ]));
  });

  it("marks nothing unread when every lookup answered, even with no records", async () => {
    const unread: string[] = [];
    await auditEmailAuth("https://example.com", () => Promise.resolve([]), unread);
    expect(unread).toEqual([]);
  });
});
