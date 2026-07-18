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
