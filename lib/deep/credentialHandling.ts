import { isTestPath, isScaffoldPath, type GithubFinding, type RepoFile } from "./githubScan";

// Two checks restored on 2026-09-07, after the pattern-check layer was deleted
// on the same day. They went out as collateral: both lived in
// `sourcePatterns.ts` and the file was removed whole, but neither was named in
// the deletion scope, and both were among the five true positives the
// fifteen-repository ledger recorded.
//
// They are back because they pass the boundary that governs this layer, stated
// in docs/STATE.md: does the evidence in hand decide the claim made?
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
// restore those. See docs/TASK-A-MEASUREMENT-2026-09-07.md.
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

export function scanCredentialHandling(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const file of files) {
    if (!CODE_RE.test(file.path)) continue;

    if (INSECURE_RANDOM_RE.test(file.content)) {
      out.push(
        f(
          `github:insecure_random:${file.path}`,
          pathSeverity(file.path, "WARNING"),
          `Security token generated with Math.random() in ${file.path}`,
          `${file.path} builds a token, secret or one-time code from Math.random(). That generator is not cryptographically secure and its output is predictable from a handful of previous values, so an attacker can guess valid ones rather than brute-forcing them. Use crypto.randomUUID(), crypto.getRandomValues(), or randomBytes from node:crypto.`
        )
      );
    }

    if (SENSITIVE_QUERY_RE.test(file.content) && URLISH_RE.test(file.content)) {
      out.push(
        f(
          `github:secret_in_url:${file.path}`,
          pathSeverity(file.path, "WARNING"),
          `Sensitive value passed in a URL query string in ${file.path}`,
          `${file.path} puts a token, password or secret in a URL query string. Query strings are written to server and proxy access logs, kept in browser history, and sent onward in the Referer header when the page links out. The value is exposed to everything on that path even when the request itself is over HTTPS. Send it in a request header or body instead.`
        )
      );
    }
  }

  return out;
}
