import { isTestPath, isScaffoldPath, type GithubFinding, type RepoFile } from "./githubScan";

// Two checks restored on 2026-09-07, after the pattern-check layer was deleted
// on the same day. They went out as collateral: both lived in
// `sourcePatterns.ts` and the file was removed whole, but neither was named in
// the deletion scope, and both were among the five true positives the
// fifteen-repository ledger recorded.
//
// They are back because they pass the boundary that governs this layer, stated
// in AGENTS.md: does the evidence in hand decide the claim made?
//
//   `?secret=${process.env.REVALIDATE_TOKEN}` inside a fetch() is a secret in a
//   URL. Nothing outside the file is needed to know that.
//
//   `cal_live_${Math.random().toString(36)}` is a token built from a
//   predictable source. Math.random() is predictable by construction.
//
// That is what separates them from injection and XSS, which assert a semantic
// property — is this value attacker-controlled, does this sink receive that
// source — the file cannot establish. Do not read this module as licence to
// restore those. The dated before/after counts are in the master ledger.
//
// Their false positives were a PATH problem, not a taint problem: every one
// read on the fifteen repositories was test scaffolding. So they take the rule
// the secret scanner has applied since August and `scanSecrets` still applies
// to committed env files — the PATH decides how loudly we speak. A hit under a
// test or scaffold path is reported one step quieter and never dropped, so the
// trade is a missed escalation rather than a missed finding.
//
// PURE — no network.

const CODE_RE = /\.(ts|tsx|js|jsx|mjs|cjs)$/i;

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({ id, severity, title, consequence, packageName: null, version: null, vulnId: null, cveId: null });

/**
 * One step quieter under a test or scaffold path.
 *
 * `isTestPath` and `isScaffoldPath` are imported rather than reimplemented:
 * they are the repository's single path classifier, already shared by
 * `scanSecrets`, `historyScan` and `clientExposure`. A second copy of this
 * judgement is how the two halves drift apart.
 */
function pathSeverity(path: string, base: GithubFinding["severity"]): GithubFinding["severity"] {
  if (!isTestPath(path) && !isScaffoldPath(path)) return base;
  return base === "CRITICAL" ? "WARNING" : base === "WARNING" ? "INFO" : base;
}

// ── A security value built from a predictable source ───────────────────────
// Math.random() is not a CSPRNG. The guard is that its result must be assigned
// to something the file itself names as a security value, so an md5 cache key
// or a React list key stays silent.
const INSECURE_RANDOM_RE =
  /\b(token|secret|otp|nonce|apikey|api_?key|session_?id|reset_?token|password|salt)\w*\s*[:=][^;\n]*Math\.random\s*\(/i;
const INSECURE_RANDOM_ALL_RE = new RegExp(INSECURE_RANDOM_RE.source, "gi");

// ── A credential carried in a URL query string ─────────────────────────────
// Two signals, so prose and ordinary query strings stay silent: a SENSITIVE
// parameter name, AND a URL-ish context. `?q=…&page=2` has no sensitive
// parameter and never fires.
// The negative lookahead is not a narrowing of the claim, it is the claim:
// `?session_id={CHECKOUT_SESSION_ID}` carries no value at all. Stripe
// substitutes that token when it builds the redirect, and both corpus-af and
// corpus-d write it verbatim into a success_url. A brace-delimited SHOUTY token
// is a template placeholder, which is the same distinction PLACEHOLDER_RE
// already draws for committed env values. `?secret=${process.env.TOKEN}`
// begins with `$`, not `{`, and still fires.
const SENSITIVE_QUERY_RE =
  /[?&](access_?token|auth_?token|api_?key|apikey|password|passwd|secret|session_?id)=(?!\{[A-Z0-9_]+\})/i;
const URLISH_RE = /(https?:\/\/|fetch\s*\(|redirect\s*\(|\.href\s*=|new URL\(|["'`]\/)/;

// Census 2026-10-06 (withheld census shown-without-agent-2026-10-06): most
// URL-query hits were calls to outside providers that require the token in the
// query (Meta Graph, WeChat, Bing), session or job ids, local addresses and
// placeholder text. Each call is judged where it is made. A credential in the
// query of a call to the app's own endpoints, or to a base this file does not
// resolve, is the app's risk (WARNING); everything else is stated as a fact
// (INFO). Nothing that fired before goes silent.
const SENSITIVE_QUERY_ALL_RE = new RegExp(SENSITIVE_QUERY_RE.source, "gi");
const OWN_BASE_RE = /(NEXTAUTH_URL|APP_URL|BASE_URL|SITE_URL|PUBLIC_URL|ORIGIN|revalidate)/i;
const LOCAL_RE = /localhost|127\.0\.0\.1|0\.0\.0\.0/;
const COMMENT_OR_PLACEHOLDER_RE = /^\s*(\/\/|\*|\/\*|#)|placeholder=|=x{3,}|=\.\.\.|=your[-_]|=<[a-z_-]+>/i;

type QueryCall = { severity: "WARNING" | "INFO"; host: string | null };

function hostOf(url: string): string | null {
  const m = /^https?:\/\/([^/\s"'`$?:]+)/.exec(url);
  return m ? m[1] : null;
}

/** Each credential-named query parameter, judged by the call it sits in. */
function queryCalls(content: string): QueryCall[] {
  const calls: QueryCall[] = [];
  const lines = content.split("\n");
  lines.forEach((line, at) => {
    for (const match of line.matchAll(SENSITIVE_QUERY_ALL_RE)) {
      const before = line.slice(0, match.index);
      // The URL as written from the start of its string literal. A
      // continuation of a URL built across lines (`...?fields=id` +
      // `&access_token=...`) is read from where it started, up to three lines
      // back (CORPUS-5, corpus-aj's Graph adapters).
      let url = before.slice(Math.max(before.lastIndexOf("`"), before.lastIndexOf('"'), before.lastIndexOf("'")) + 1);
      if (/^\s*[`"']?$/.test(before)) {
        const start = lines.slice(Math.max(0, at - 3), at).reverse().find((l) => /[`"'](https?:\/\/|\$\{|\/)/.test(l));
        if (start) url = start.slice(start.search(/[`"'](https?:\/\/|\$\{|\/)/) + 1);
      }
      if (/session_?id/i.test(match[1]) || COMMENT_OR_PLACEHOLDER_RE.test(line) || LOCAL_RE.test(line)) {
        calls.push({ severity: "INFO", host: null });
        continue;
      }
      if (/^https?:\/\//.test(url)) { calls.push({ severity: "INFO", host: hostOf(url) }); continue; }
      const base = /^\$\{([^}]+)\}/.exec(url);
      if (base) {
        const expr = base[1].trim();
        if (OWN_BASE_RE.test(expr)) { calls.push({ severity: "WARNING", host: null }); continue; }
        const name = /^[A-Za-z_$][\w$]*$/.test(expr) ? expr : null;
        const declared = name ? new RegExp(`\\b(?:const|let|var)\\s+${name.replace(/\$/g, "\\$")}\\s*=\\s*["'\`](https?:\\/\\/[^"'\`]+)`).exec(content) : null;
        const host = declared ? hostOf(declared[1]) : null;
        // A base this file does not resolve (a config property, a request
        // field) was an outside service on every one read (census, CORPUS-5,
        // CORPUS-6); the app's own bases are relative or named above.
        calls.push({ severity: "INFO", host: host && !LOCAL_RE.test(host) ? host : null });
        continue;
      }
      // A relative path is this app's own endpoint; anything else is a base
      // this file does not resolve. Both stay the app's risk.
      calls.push({ severity: "WARNING", host: null });
    }
  });
  return calls;
}

/** Findings for credentials handled unsafely in code: credentials sent in a URL
 * query, and tokens or codes drawn from insecure randomness. */
export function scanCredentialHandling(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const file of files) {
    if (!CODE_RE.test(file.path)) continue;

    const random = file.content.match(INSECURE_RANDOM_ALL_RE) ?? [];
    if (random.length > 0) {
      // A session id names a conversation or a cart as often as a login, and
      // a plural "tokens" is a count of model tokens (CORPUS-6: none of six
      // was a credential). Those are stated as facts; a code, secret or reset
      // token stays a warning.
      const guards = random.some((m) => !/^(session_?id|tokens)\b/i.test(m));
      out.push(
        f(
          `github:insecure_random:${file.path}`,
          pathSeverity(file.path, guards ? "WARNING" : "INFO"),
          `Security token generated with Math.random() in ${file.path}`,
          `${file.path} builds a token, secret or one-time code from Math.random(). That generator is not cryptographically secure and its output is predictable from a handful of previous values, so an attacker can guess valid ones rather than brute-forcing them. Use crypto.randomUUID(), crypto.getRandomValues(), or randomBytes from node:crypto.`
        )
      );
    }

    const calls = SENSITIVE_QUERY_RE.test(file.content) && URLISH_RE.test(file.content) ? queryCalls(file.content) : [];
    if (calls.length > 0) {
      const own = calls.some((c) => c.severity === "WARNING");
      const host = calls.find((c) => c.host)?.host ?? null;
      out.push(
        f(
          `github:secret_in_url:${file.path}`,
          pathSeverity(file.path, own ? "WARNING" : "INFO"),
          `Sensitive value passed in a URL query string in ${file.path}`,
          own
            ? `${file.path} puts a token, password or secret in a URL query string. Query strings are written to server and proxy access logs, kept in browser history, and sent onward in the Referer header when the page links out. The value is exposed to everything on that path even when the request itself is over HTTPS. Send it in a request header or body instead.`
            : `${file.path} carries a token-named value in a URL query string only in calls to ${host ?? "an outside service, a local address, or as a session id"}, not to this app's own endpoints. Some providers require the token there; it lands in their logs rather than yours. Prefer a header where the provider accepts one.`
        )
      );
    }
  }

  return out;
}
