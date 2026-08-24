import type { Severity } from "@/lib/types";
import { assertPublicHttpsUrl } from "@/lib/security/ssrfGuard";

// Dynamic exposed-path probes against the customer's LIVE app URL. Complements
// the scanner's checkSecretsExposure (which already covers /.env* variants) with
// the classic vibecoded-app leaks it doesn't: a publicly-served .git repo,
// database dumps, and committed credential files.
//
// PRECISION: modern SPAs/static hosts answer 200 with index.html for ANY path
// (catch-all routing), so a bare 200 means nothing. Every probe requires a
// content SIGNATURE specific to the file, and HTML responses are treated as the
// catch-all and ignored. classifyExposed is pure + unit-tested.

export interface ExposedFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
}

interface Probe {
  path: string;
  group: string; // findings dedup by group (e.g. .git found via HEAD or config = one finding)
  severity: Severity;
  title: string;
  sig: RegExp;
  consequence: string;
}

const PROBES: Probe[] = [
  {
    path: "/.git/HEAD", group: "git_exposed", severity: "CRITICAL", sig: /ref:\s*refs\//,
    title: "Your Git repository is publicly served",
    consequence:
      "Your .git directory is reachable over the web, exposing your full source history (and any secret ever committed to it). Block /.git at your host/CDN and make sure it isn't part of your deploy output.",
  },
  {
    path: "/.git/config", group: "git_exposed", severity: "CRITICAL", sig: /\[core\]/,
    title: "Your Git repository is publicly served",
    consequence:
      "Your .git directory is reachable over the web, exposing your full source history. Block /.git at your host/CDN and make sure it isn't part of your deploy output.",
  },
  {
    path: "/backup.sql", group: "db_dump_exposed", severity: "CRITICAL",
    sig: /(insert\s+into|create\s+table|copy\s+public\.|postgresql database dump)/i,
    title: "A database dump is publicly served",
    consequence:
      "A .sql dump of your database is downloadable over the web — that's every row of your data, publicly. Remove it from your deploy immediately and rotate anything sensitive it contained.",
  },
  {
    path: "/dump.sql", group: "db_dump_exposed", severity: "CRITICAL",
    sig: /(insert\s+into|create\s+table|copy\s+public\.|postgresql database dump)/i,
    title: "A database dump is publicly served",
    consequence:
      "A .sql dump of your database is downloadable over the web — that's every row of your data, publicly. Remove it from your deploy immediately and rotate anything sensitive it contained.",
  },
  {
    path: "/database.sql", group: "db_dump_exposed", severity: "CRITICAL",
    sig: /(insert\s+into|create\s+table|copy\s+public\.|postgresql database dump)/i,
    title: "A database dump is publicly served",
    consequence:
      "A .sql dump of your database is downloadable over the web — that's every row of your data, publicly. Remove it from your deploy immediately and rotate anything sensitive it contained.",
  },
  {
    path: "/.npmrc", group: "npmrc_exposed", severity: "WARNING", sig: /_authToken=|_auth=/,
    title: "An .npmrc with an auth token is publicly served",
    consequence:
      "Your .npmrc is reachable over the web and contains a registry auth token. Remove it from your deploy and rotate the token.",
  },
  {
    path: "/.aws/credentials", group: "aws_creds_exposed", severity: "CRITICAL", sig: /aws_access_key_id/i,
    title: "AWS credentials are publicly served",
    consequence:
      "An AWS credentials file is downloadable over the web. Remove it and rotate the access key immediately in IAM.",
  },
  {
    path: "/.ssh/id_rsa", group: "ssh_key_exposed", severity: "CRITICAL", sig: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    title: "A private SSH key is publicly served",
    consequence:
      "A private SSH key is downloadable over the web. Remove it and rotate the key pair immediately.",
  },
];

// A catch-all SPA/static host serving index.html for an unknown path.
function looksLikeHtml(body: string): boolean {
  return /<!doctype html|<html[\s>]/i.test(body.slice(0, 500));
}

// Pure classifier for one probe's response.
export function classifyExposed(
  probe: Pick<Probe, "group" | "severity" | "title" | "sig" | "consequence">,
  status: number,
  body: string
): ExposedFinding | null {
  if (status !== 200) return null;
  if (looksLikeHtml(body)) return null; // catch-all, not the real file
  if (!probe.sig.test(body)) return null;
  return { id: `exposed:${probe.group}`, severity: probe.severity, title: probe.title, consequence: probe.consequence };
}

const TIMEOUT_MS = 5_000;
const MAX_BODY = 20_000; // signatures live near the top; don't slurp huge files

// Probe every path against the app URL. Best-effort: any network error on a path
// is treated as "not exposed" (safe). Dedups by group.
export async function probeExposedPaths(appUrl: string): Promise<ExposedFinding[]> {
  const base = appUrl.replace(/\/+$/, "");
  try {
    await assertPublicHttpsUrl(base);
  } catch {
    return []; // resolves to a private/internal address — refuse to probe it
  }
  const found = new Map<string, ExposedFinding>();

  await Promise.all(
    PROBES.map(async (probe) => {
      try {
        const res = await fetch(`${base}${probe.path}`, {
          signal: AbortSignal.timeout(TIMEOUT_MS),
          redirect: "manual", // a redirect to a login/app page is not the file
        });
        const body = (await res.text().catch(() => "")).slice(0, MAX_BODY);
        const finding = classifyExposed(probe, res.status, body);
        if (finding && !found.has(finding.id)) found.set(finding.id, finding);
      } catch {
        /* network error / timeout = safe */
      }
    })
  );

  return [...found.values()];
}

// Exposed for tests.
export const _PROBES = PROBES;
