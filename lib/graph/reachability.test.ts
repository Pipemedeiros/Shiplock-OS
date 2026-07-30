import { describe, expect, it } from "vitest";
import {
  assessReachability,
  buildReachabilityIndex,
  fileFromFindingId,
  isEntryPoint,
  isNonProductionPath,
  tableFromFindingId,
  triageByReachability,
} from "./reachability";
import { collectRoutes } from "./routeInventory";

const file = (path: string, content: string) => ({ path, content });

const app = [
  file("app/api/invoices/route.ts", `import { fmt } from "@/lib/fmt";\nexport async function GET(){ return supabase.from("invoices").select() }`),
  file("app/page.tsx", `import { Hero } from "@/components/Hero";\nexport default function Page(){ return <Hero/> }`),
  file("lib/fmt.ts", `export const fmt = (x) => x;`),
  file("components/Hero.tsx", `export const Hero = () => null;`),
  file("scripts/seed.ts", `eval(process.argv[2]);`),
  file("lib/orphan.ts", `document.body.innerHTML = userInput;`),
  file("lib/fmt.test.ts", `import { fmt } from "./fmt";`),
];

const index = () => buildReachabilityIndex({ files: app, routes: collectRoutes(app) });

describe("entry points", () => {
  it("recognises the ways a Next.js app starts executing", () => {
    for (const p of [
      "app/api/x/route.ts",
      "app/page.tsx",
      "app/dashboard/layout.tsx",
      "app/actions.ts",
      "middleware.ts",
      "pages/api/x.ts",
      "src/app/page.tsx",
    ]) {
      expect(isEntryPoint(p), p).toBe(true);
    }
  });

  // Dogfooding found these three called dead while they run in production.
  // Next.js invokes them by file convention, at the app/ root.
  it("recognises root-level Next.js special files", () => {
    for (const p of [
      "app/robots.ts",
      "app/sitemap.ts",
      "app/manifest.ts",
      "app/opengraph-image.tsx",
      "app/twitter-image.tsx",
      "app/icon.tsx",
      "app/apple-icon.tsx",
      "app/not-found.tsx",
      "app/global-error.tsx",
    ]) {
      expect(isEntryPoint(p), p).toBe(true);
    }
  });

  it("recognises the same special files nested deeply", () => {
    for (const p of ["app/(d)/dashboard/settings/page.tsx", "app/blog/[slug]/opengraph-image.tsx"]) {
      expect(isEntryPoint(p), p).toBe(true);
    }
  });

  it("does not treat an ordinary module as an entry point", () => {
    for (const p of ["lib/db.ts", "components/Form.tsx", "scripts/seed.ts"]) {
      expect(isEntryPoint(p), p).toBe(false);
    }
  });
});

describe("non-production paths", () => {
  it("recognises test and tooling code", () => {
    for (const p of ["scripts/seed.ts", "e2e/login.spec.ts", "lib/x.test.ts", "__tests__/a.ts", "docs/example.ts"]) {
      expect(isNonProductionPath(p), p).toBe(true);
    }
  });

  it("does not misclassify application code", () => {
    for (const p of ["lib/db.ts", "app/api/x/route.ts", "components/Contest.tsx"]) {
      expect(isNonProductionPath(p), p).toBe(false);
    }
  });
});

describe("id parsing", () => {
  it("extracts a file from a namespaced finding id", () => {
    expect(fileFromFindingId("acme/app::github:xss_sink:eval_call:lib/orphan.ts")).toBe("lib/orphan.ts");
  });

  it("returns null when the id carries no file", () => {
    expect(fileFromFindingId("email_auth:spf_missing")).toBeNull();
    expect(fileFromFindingId("advisor:rls_policy_always_true:public.invoices")).toBeNull();
  });

  it("extracts a table from advisor and policy ids", () => {
    expect(tableFromFindingId("advisor:rls_policy_always_true:public.invoices")).toBe("invoices");
    expect(tableFromFindingId("policy:public.orders:p:unrestricted_read")).toBe("orders");
  });
});

describe("verdicts", () => {
  it("marks a file reachable from an API route", () => {
    const v = assessReachability("acme/app::github:xss_sink:x:lib/fmt.ts", index());
    expect(v.state).toBe("reachable");
    expect(v.scoreDelta).toBeGreaterThan(0);
  });

  it("marks a file reachable from a page", () => {
    expect(assessReachability("acme/app::github:xss_sink:x:components/Hero.tsx", index()).state).toBe("reachable");
  });

  it("marks the entry point itself reachable", () => {
    expect(assessReachability("acme/app::github:xss_sink:x:app/api/invoices/route.ts", index()).state).toBe("reachable");
  });

  it("demotes a finding in a build script", () => {
    const v = assessReachability("acme/app::github:xss_sink:eval_call:scripts/seed.ts", index());
    expect(v.state).toBe("no_path_found");
    expect(v.scoreDelta).toBeLessThan(0);
    expect(v.reason).toContain("not exposed to your users");
  });

  it("demotes a finding in a test file", () => {
    expect(assessReachability("acme/app::github:xss_sink:x:lib/fmt.test.ts", index()).state).toBe("no_path_found");
  });

  // The honesty requirement: we cannot resolve every path, and the copy says so.
  it("admits uncertainty rather than claiming a file is dead", () => {
    const v = assessReachability("acme/app::github:xss_sink:x:lib/orphan.ts", index());
    expect(v.state).toBe("no_path_found");
    expect(v.reason).toContain("probably not live");
    expect(v.reason).toContain("does not resolve dynamically-built paths");
  });

  it("promotes a policy finding on a table the API actually reads", () => {
    const v = assessReachability("advisor:rls_policy_always_true:public.invoices", index());
    expect(v.state).toBe("reachable");
    expect(v.scoreDelta).toBeGreaterThan(0);
  });

  // Still wrong, still reported — just less urgent.
  it("demotes a policy finding on a table no route reads, without dismissing it", () => {
    const v = assessReachability("advisor:rls_policy_always_true:public.audit_log", index());
    expect(v.state).toBe("no_path_found");
    expect(v.reason).toContain("still wrong and still worth fixing");
  });

  it("returns unknown for a finding with neither a file nor a table", () => {
    expect(assessReachability("email_auth:spf_missing", index()).state).toBe("unknown");
  });

  // THE critical safeguard: no entry points means we would call everything dead.
  it("returns unknown for EVERYTHING when no entry points were found", () => {
    const blind = buildReachabilityIndex({ files: [file("lib/a.ts", "x")], routes: [] });
    expect(blind.hasEntryPoints).toBe(false);
    for (const id of [
      "acme/app::github:xss_sink:x:lib/a.ts",
      "acme/app::github:xss_sink:x:scripts/seed.ts",
      "advisor:rls_policy_always_true:public.invoices",
    ]) {
      expect(assessReachability(id, blind).state, id).toBe("unknown");
    }
  });
});

describe("triage", () => {
  const findings = [
    { id: "acme/app::github:xss_sink:eval_call:scripts/seed.ts", severity: "CRITICAL", title: "eval in seed script" },
    { id: "acme/app::github:xss_sink:inner_html:lib/fmt.ts", severity: "WARNING", title: "innerHTML in live code" },
    { id: "acme/app::github:xss_sink:x:lib/orphan.ts", severity: "CRITICAL", title: "innerHTML in orphan" },
  ];

  it("ranks a live WARNING above a CRITICAL that only exists in a build script", () => {
    const triaged = triageByReachability(findings, index());
    expect(triaged[0].finding.title).toBe("innerHTML in orphan");
    const live = triaged.findIndex((t) => t.finding.title === "innerHTML in live code");
    const script = triaged.findIndex((t) => t.finding.title === "eval in seed script");
    expect(live).toBeLessThan(script);
  });

  // The property that makes this feature safe to ship.
  it("NEVER drops a finding — output length always equals input length", () => {
    expect(triageByReachability(findings, index())).toHaveLength(findings.length);
    const blind = buildReachabilityIndex({ files: [], routes: [] });
    expect(triageByReachability(findings, blind)).toHaveLength(findings.length);
  });

  it("attaches the reasoning to every finding", () => {
    for (const t of triageByReachability(findings, index())) {
      expect(t.reachability.state).toBeTruthy();
      if (t.reachability.state !== "unknown") expect(t.reachability.reason.length).toBeGreaterThan(20);
    }
  });

  it("leaves ordering by severity alone when reachability is unknown", () => {
    const blind = buildReachabilityIndex({ files: [], routes: [] });
    const triaged = triageByReachability(
      [
        { id: "email_auth:spf_missing", severity: "WARNING", title: "w" },
        { id: "email_auth:dmarc_missing", severity: "CRITICAL", title: "c" },
      ],
      blind
    );
    expect(triaged[0].finding.title).toBe("c");
  });

  it("is deterministic for equal ranks", () => {
    const input = [
      { id: "b:x", severity: "CRITICAL", title: "b" },
      { id: "a:x", severity: "CRITICAL", title: "a" },
    ];
    expect(triageByReachability(input, index()).map((t) => t.finding.title)).toEqual(["a", "b"]);
  });

  it("handles an empty finding list", () => {
    expect(triageByReachability([], index())).toEqual([]);
  });
});
