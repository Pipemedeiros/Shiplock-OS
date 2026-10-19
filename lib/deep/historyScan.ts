import { isCommentLine, isTestPath, looksSynthetic, type GithubFinding } from "./githubScan";

// C2 — secrets that were committed, then removed.
//
// The most misunderstood finding we produce, and the reason it is worth having:
// deleting a secret from a file does not remove it from the repository. Every
// commit that ever contained it is still there, reachable by anyone who can
// clone — and on a public repo, by anyone at all, forever. GitHub even serves
// orphaned commits over the API after a force-push.
//
// So the common story ends badly. Someone commits a key, notices within the
// hour, commits a fix, and moves on believing it handled. The key is still in
// history, still valid, and the developer has stopped looking for it. Meanwhile
// credential-harvesting bots index public commits within minutes of a push.
//
// WHAT MAKES THIS FINDING DIFFERENT: for every other class we say "fix the
// code". Here the code is ALREADY fixed, and the only action that helps is
// rotating the credential. A fix PR would be actively misleading, so this never
// produces one.
//
// BOUNDED HARD. Reading history costs an API call per commit, and a repository
// can have a hundred thousand of them. The caps below are deliberately small:
// this is not a forensic tool, it is a check that catches the recent mistake
// while it is still worth catching.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

/** Vendor-issued credential shapes. Every one is distinctive, not a heuristic.
 * `current` is the working-tree scan's id for the same class (githubScan),
 * which is what githubRun passes as stillPresent. */
const HISTORY_SECRETS: { id: string; label: string; re: RegExp; rotate: string; current?: string }[] = [
  { id: "supabase_secret", label: "a Supabase secret key", re: /\bsb_secret_[A-Za-z0-9_-]{10,}/, rotate: "Supabase → Project Settings → API Keys", current: "supabase_service_key" },
  { id: "stripe_live", label: "a live Stripe secret key", re: /\bsk_live_[A-Za-z0-9]{16,}/, rotate: "the Stripe dashboard" },
  { id: "aws_key", label: "an AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/, rotate: "AWS IAM", current: "aws_access_key" },
  { id: "anthropic", label: "an Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,}/, rotate: "the Anthropic console" },
  { id: "openai", label: "an OpenAI API key", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/, rotate: "the OpenAI dashboard", current: "openai_key" },
  { id: "github_token", label: "a GitHub token", re: /\bgh[pso]_[A-Za-z0-9]{20,}/, rotate: "GitHub → Developer settings" },
  { id: "private_key", label: "a PEM private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, rotate: "wherever the key pair is issued", current: "private_key" },
  { id: "slack_token", label: "a Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, rotate: "the Slack app configuration" },
];

/** Hard caps. This is a check, not a forensic tool. */
export const MAX_COMMITS = 200;
export const MAX_PATCH_BYTES = 200_000;

export interface CommitPatch {
  sha: string;
  /** Short message, for naming the commit in the finding. */
  message: string;
  /** Combined diff text for the commit. */
  patch: string;
  /** ISO date, so we can say how long it has been exposed. */
  date: string;
}

export interface HistoryHit {
  secretId: string;
  label: string;
  sha: string;
  date: string;
  rotate: string;
}

/**
 * Finds credentials in commit diffs.
 *
 * Matches ADDED lines only. A diff contains both sides, so scanning the whole
 * patch would flag the very commit that REMOVED a secret — reporting the fix as
 * the problem, at the moment the developer did the right thing.
 */
/**
 * Added lines, grouped by the file they were added to.
 *
 * The path is the whole point. Scanning a combined diff as one blob loses which
 * file each line came from, and without that this check reported ShipLock's own
 * dashboard with six credential classes -- a live Stripe key, a PEM private
 * key, a Slack token -- every one of them a fixture inside
 * lib/deep/historyScan.test.ts, added by the very commit that created this
 * file. The scanner found its own test data and called it a leak.
 */
function addedLinesByFile(patch: string): { path: string; line: string }[] {
  const out: { path: string; line: string }[] = [];
  let path = "";
  for (const line of patch.split("\n")) {
    const header = /^diff --git a\/(?:.+) b\/(.+)$/.exec(line);
    if (header) { path = header[1]; continue; }
    const plus = /^\+\+\+ b\/(.+)$/.exec(line);
    if (plus) { path = plus[1]; continue; }
    if (line.startsWith("+") && !line.startsWith("+++")) out.push({ path, line });
  }
  return out;
}

export function scanPatches(commits: CommitPatch[]): HistoryHit[] {
  const hits: HistoryHit[] = [];
  const seen = new Set<string>();

  for (const commit of commits.slice(0, MAX_COMMITS)) {
    const patch = commit.patch.slice(0, MAX_PATCH_BYTES);
    const added = addedLinesByFile(patch);
    if (added.length === 0) continue;

    for (const secret of HISTORY_SECRETS) {
      // The PATH decides how loudly we speak and the VALUE decides whether we
      // speak at all -- the rule githubScan settled on, applied here too. A
      // real key committed in a test file is still a real key, so a
      // real-LOOKING value in test scaffolding still reports.
      const real = added.some(({ path, line }) => {
        const m = secret.re.exec(line);
        if (!m) return false;
        if (isTestPath(path) && looksSynthetic(m[0], line)) return false;
        // A vendor's published example quoted in a comment is documentation,
        // wherever it lives. Amazon publishes AKIAIOSFODNN7EXAMPLE itself, and
        // this file's own source comments explaining that were reported as a
        // committed AWS key.
        if (isCommentLine(line.slice(1)) && looksSynthetic(m[0], line)) return false;
        return true;
      });
      if (!real) continue;
      // One finding per secret class, attributed to the earliest commit we saw
      // introduce it.
      if (seen.has(secret.id)) continue;
      seen.add(secret.id);
      hits.push({
        secretId: secret.id,
        label: secret.label,
        sha: commit.sha,
        date: commit.date,
        rotate: secret.rotate,
      });
    }
  }

  return hits;
}

function daysSince(iso: string): number | null {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  return Math.max(0, Math.floor((Date.now() - then) / 86_400_000));
}

/**
 * Turns hits into findings.
 *
 * @param stillPresent secret ids the CURRENT scan also found in working files.
 *        Those are already reported by the committed-secrets check, and saying
 *        it twice would be the same problem on the board in two places.
 */
export function historyFindings(
  hits: HistoryHit[],
  repoIsPublic: boolean,
  stillPresent: Set<string> = new Set()
): GithubFinding[] {
  return hits
    .filter((hit) => !stillPresent.has(hit.secretId)
      && !stillPresent.has(HISTORY_SECRETS.find((secret) => secret.id === hit.secretId)?.current ?? ""))
    .map((hit) => {
      const days = daysSince(hit.date);
      const age = days === null ? "" : days === 0 ? " today" : ` ${days} day${days === 1 ? "" : "s"} ago`;

      return f(
        `github:history_secret:${hit.secretId}:${hit.sha.slice(0, 12)}`,
        repoIsPublic ? "CRITICAL" : "WARNING",
        `${hit.label} was committed${age} and is still in your history`,
        `Commit ${hit.sha.slice(0, 8)} added ${hit.label}. It is not in the files we read today, but deleting a secret from a file does not remove it from the repository: every commit that contained it is still readable by anyone who can clone. ` +
          (repoIsPublic
            ? `This repository is public, so that means anyone at all, and credential-harvesting bots index public commits within minutes of a push. Treat this key as compromised rather than at risk. `
            : `This repository is private, so the exposure is limited to people with access, and that includes every past collaborator, every fork, and anything that has ever cloned it. `) +
          `Rotating the key is the only action that helps, at ${hit.rotate}. Rewriting history does not reliably help: GitHub serves orphaned commits over the API after a force-push, and any existing clone or fork keeps its copy. ` +
          `We are not opening a pull request for this, because there is nothing to change in your code. That is exactly why this one gets missed.`
      );
    });
}
