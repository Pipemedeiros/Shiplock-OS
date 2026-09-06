import { describe, expect, it } from "vitest";
import { scanWeakCrypto, scanClientXss, scanSecretsInUrl, scanInjection, scanCodePatterns } from "./sourcePatterns";
import type { RepoFile } from "./githubScan";

const file = (path: string, content: string): RepoFile => ({ path, content });

describe("scanWeakCrypto", () => {
  it("flags md5/sha1 in a password context", () => {
    const r = scanWeakCrypto([file("lib/auth.ts", `const hash = createHash("md5").update(password).digest("hex");`)]);
    expect(r).toHaveLength(1);
    expect(r[0].id).toContain("weak_hash");
  });
  it("does NOT flag md5 used for a non-password cache key", () => {
    expect(scanWeakCrypto([file("lib/cache.ts", `const key = createHash("md5").update(url).digest("hex");`)])).toEqual([]);
  });
  it("flags Math.random() feeding a security token", () => {
    const r = scanWeakCrypto([file("lib/token.ts", `const resetToken = Math.random().toString(36);`)]);
    expect(r).toHaveLength(1);
    expect(r[0].id).toContain("insecure_random");
  });
  it("does NOT flag Math.random() for a non-security value", () => {
    expect(scanWeakCrypto([file("ui/anim.ts", `const jitter = Math.random() * 10;`)])).toEqual([]);
  });
});

describe("scanClientXss", () => {
  it("flags dangerouslySetInnerHTML", () => {
    const r = scanClientXss([file("app/post.tsx", `<div dangerouslySetInnerHTML={{ __html: body }} />`)]);
    expect(r[0].id).toContain("dangerously_set_html");
  });
  it("flags an innerHTML assignment", () => {
    expect(scanClientXss([file("ui/x.ts", `el.innerHTML = userInput;`)])[0].id).toContain("inner_html_assign");
  });
  it("flags eval and wildcard postMessage", () => {
    const ids = scanClientXss([file("ui/y.ts", `eval(payload); window.parent.postMessage(data, "*");`)]).map((x) => x.id);
    expect(ids.some((i) => i.includes("eval_call"))).toBe(true);
    expect(ids.some((i) => i.includes("postmessage_wildcard"))).toBe(true);
  });
  it("stays quiet on safe rendering", () => {
    expect(scanClientXss([file("app/post.tsx", `<div>{body}</div>`)])).toEqual([]);
  });
});

describe("scanSecretsInUrl", () => {
  it("flags an access_token in a URL query string", () => {
    const r = scanSecretsInUrl([file("lib/api.ts", "const u = `https://api.example.com/data?access_token=${t}`;")]);
    expect(r[0].id).toContain("secret_in_url");
  });
  it("flags a password in a fetch URL", () => {
    expect(scanSecretsInUrl([file("lib/api.ts", `fetch("/login?password=" + pw)`)]).length).toBe(1);
  });
  it("does NOT flag a normal query param", () => {
    expect(scanSecretsInUrl([file("lib/api.ts", "fetch(`/search?q=${term}&page=2`)")])).toEqual([]);
  });
});

describe("scanInjection", () => {
  it("flags interpolated raw SQL (template)", () => {
    const r = scanInjection([file("api/u.ts", "const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);")]);
    expect(r[0].id).toContain("sql_injection");
    expect(r[0].severity).toBe("CRITICAL");
  });
  it("flags concatenated SQL in a query call", () => {
    const r = scanInjection([file("api/u.ts", `client.query("SELECT * FROM t WHERE name = '" + name + "'")`)]);
    expect(r.some((x) => x.id.includes("sql_injection"))).toBe(true);
  });
  it("flags command injection via interpolated exec", () => {
    const r = scanInjection([file("api/run.ts", "execSync(`convert ${file} out.png`)")]);
    expect(r[0].id).toContain("command_injection");
  });
  it("flags path traversal from request input", () => {
    const r = scanInjection([file("api/dl.ts", "fs.readFile(req.query.path, cb)")]);
    expect(r[0].id).toContain("path_traversal");
  });
  it("flags open redirect to a user-supplied target", () => {
    const r = scanInjection([file("api/go.ts", "return NextResponse.redirect(req.nextUrl.searchParams.get('to'))")]);
    expect(r[0].id).toContain("open_redirect");
  });
  it("does NOT flag parameterized SQL or static queries", () => {
    expect(scanInjection([file("api/u.ts", "db.query('SELECT * FROM users WHERE id = $1', [id])")])).toEqual([]);
    expect(scanInjection([file("api/u.ts", "db.query(`SELECT count(*) FROM users`)")])).toEqual([]);
  });
  it("does NOT flag a static redirect or allow-listed file read", () => {
    expect(scanInjection([file("api/go.ts", "return NextResponse.redirect('/dashboard')")])).toEqual([]);
    expect(scanInjection([file("api/dl.ts", "fs.readFile('./public/logo.png', cb)")])).toEqual([]);
  });
});

describe("scanCodePatterns — clean fixture stays silent (no false positives)", () => {
  it("no findings on secure code", () => {
    const clean: RepoFile[] = [
      file("lib/token.ts", `const t = crypto.randomUUID();`),
      file("lib/auth.ts", `// Supabase Auth handles password hashing`),
      file("app/post.tsx", `<article>{content}</article>`),
      file("lib/api.ts", "fetch('/data', { headers: { Authorization: `Bearer ${t}` } })"),
    ];
    expect(scanCodePatterns(clean)).toEqual([]);
  });
});

// BLOCKER 1 (2026-09-06). The first sql_injection pattern matched any template
// literal holding a standalone SQL keyword plus any interpolation, so it fired
// on CSS declarations, error strings and console messages. Over a full archive
// it produced 155 of 178 criticals on seven new repositories and 172 on the
// five originally-validated corpora. A SQL keyword is only evidence when it
// sits in a SQL EXECUTION CONTEXT.
describe("sql injection needs an execution context, not a keyword", () => {
  const scan = (content: string) => scanCodePatterns([{ path: "a/b.ts", content }]).filter((f) => f.id.includes("sql_injection"));

  it("DROP a styled-components CSS literal (outline Button.tsx)", () => {
    expect(scan("const B = styled.button`\n  cursor: var(--pointer);\n  user-select: none;\n  ${undraggableOnDesktop()}\n`;")).toHaveLength(0);
  });

  it("DROP an error message that contains the word update (directus payload.ts)", () => {
    expect(scan("throw new Error(`Can't update nested record \"${relation.collection}.${relation.field}\" without a field`);")).toHaveLength(0);
  });

  it("DROP a console message that mentions updated rows (immich)", () => {
    expect(scan("console.log(`Matching database file paths were updated successfully! Set X=${newValue} and restart.`);")).toHaveLength(0);
  });

  it("DROP a Prisma tagged template, which parameterises its interpolations", () => {
    expect(scan("const rows = await prisma.$queryRaw`SELECT id FROM users WHERE id = ${userId}`;")).toHaveLength(0);
  });

  it("KEEP an explicit unsafe raw call", () => {
    expect(scan("await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);")).toHaveLength(1);
  });

  it("KEEP a template with SQL interpolated into a query call", () => {
    expect(scan("await db.query(`SELECT * FROM users WHERE id = ${id}`);")).toHaveLength(1);
  });

  it("KEEP knex.raw with an interpolation", () => {
    expect(scan("knex.raw(`select * from t where id = ${id}`)")).toHaveLength(1);
  });

  it("KEEP string concatenation into a query call", () => {
    expect(scan("db.query('SELECT * FROM users WHERE id = ' + id)")).toHaveLength(1);
  });

  it("DROP a query call with no SQL keyword and no interpolation", () => {
    expect(scan("await page.query(`something`);")).toHaveLength(0);
  });
});

// BLOCKER 4 (2026-09-06). The secret scanner has applied "the PATH decides how
// loudly we speak" since August; the injection scanner never received it. Of 81
// injection criticals across fifteen repositories, 25 sat in paths isTestPath
// already recognises, 7 more in `integration-tests/` (which TEST_PATH_RE misses
// because it requires the segment to be exactly `tests`), and 7 in `scripts/`.
describe("injection findings follow the same path rule as secrets", () => {
  const sev = (path: string, content: string) =>
    scanCodePatterns([{ path, content }]).find((f) => f.id.includes("injection"))?.severity;
  const SQLI = "await db.execute(`SELECT * FROM users WHERE id = ${id}`);";

  it("still CRITICAL in production code", () => {
    expect(sev("apps/web/lib/analytics/get-analytics.ts", SQLI)).toBe("CRITICAL");
  });

  it("quieter in a test directory", () => {
    expect(sev("server/test/utils.ts", SQLI)).toBe("WARNING");
  });

  it("quieter in integration-tests, which the segment pattern used to miss", () => {
    expect(sev("integration-tests/helpers/use-db.js", SQLI)).toBe("WARNING");
  });

  it("quieter in a build or release script", () => {
    expect(sev("scripts/release.ts", "execSync(`uv version --directory ml ${v}`)")).toBe("WARNING");
  });

  // The trade: a migration runs in production against the real database, so it
  // is NOT scaffolding and is deliberately left at CRITICAL.
  it("still CRITICAL in a migration, which runs for real", () => {
    expect(sev("server/migrations/20171225143838-set-admins.js", SQLI)).toBe("CRITICAL");
  });

  it("is never silent — a quieted finding is still reported", () => {
    expect(scanCodePatterns([{ path: "server/test/utils.ts", content: SQLI }])).toHaveLength(1);
  });
});
