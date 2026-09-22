import type { FixableFinding } from "./lane";

// Real fixes, not fix requests.
//
// Until now a "fix PR" committed a Markdown file saying "apply the change below
// yourself". That is the copy-paste problem in a nicer wrapper — the thing the
// owner objected to, and the thing the autonomy doctrine calls out: anything
// ending in "...and then you go do it" has failed the brief.
//
// A codemod produces the actual edited file. The customer reviews a diff of
// their own code, not instructions.
//
// THE RULE THAT DECIDES WHAT BELONGS HERE: a codemod is only allowed where the
// correct output is MECHANICAL — determined entirely by the input, with no
// judgement about what the application is supposed to do. Adding a security
// header is mechanical. Rewriting an authorization check is not, because the
// right answer depends on intent that lives in the customer's head and nowhere
// in the code. AGENTS.md is explicit that application logic is never
// machine-authored, and this module does not weaken that — it takes the
// mechanical cases OFF the human's plate so the judgement cases get their
// attention.
//
// Every codemod is REVERSIBLE by construction: it produces a complete new file
// body, so reverting is reverting the PR. And every one is exact — if a
// transform cannot find what it expects, it returns null rather than guessing,
// because a codemod that half-applies is worse than one that does not run.

export interface CodemodResult {
  path: string;
  /** Complete new file contents. */
  content: string;
  /** One-line summary for the PR body. */
  description: string;
}

export interface CodemodInput {
  path: string;
  content: string;
}

export type Codemod = (input: CodemodInput, finding: FixableFinding) => CodemodResult | null;

// ── Security headers ───────────────────────────────────────────────────────

const HEADERS_BLOCK = `          { key: "X-Frame-Options", value: "DENY" },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },`;

/**
 * Adds the standard security headers to a Next.js config.
 *
 * Mechanical: the correct set does not depend on what the app does. Deliberately
 * does NOT touch Content-Security-Policy — CSP needs a per-request nonce and
 * belongs in middleware (see AGENTS.md; a static CSP silently breaks every
 * button on the site). A codemod that "helpfully" added one here would take an
 * app down.
 */
export const addSecurityHeaders: Codemod = ({ path, content }) => {
  if (!/next\.config\.(ts|js|mjs)$/.test(path)) return null;
  // Already present — do nothing rather than duplicate.
  if (/X-Content-Type-Options/.test(content)) return null;
  // An existing headers() function means merging, which is a judgement call
  // about ordering and overrides. Refuse rather than mangle it.
  if (/async\s+headers\s*\(/.test(content)) return null;

  const configOpen = /(const\s+\w+\s*(?::\s*\w+)?\s*=\s*\{)/.exec(content);
  if (!configOpen) return null;

  const insertAt = configOpen.index + configOpen[0].length;
  const block = `
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
${HEADERS_BLOCK}
        ],
      },
    ];
  },`;

  return {
    path,
    content: content.slice(0, insertAt) + block + content.slice(insertAt),
    description: "add standard security response headers",
  };
};

// ── Public-prefixed secret rename ──────────────────────────────────────────

/**
 * Renames a `NEXT_PUBLIC_*` variable that holds a secret, everywhere it appears.
 *
 * Mechanical: the new name is derived from the old one. Does NOT rotate the key
 * — nothing in a repository can — so the PR body says so, because a rename that
 * reads as "fixed" while the leaked value stays live is worse than no change.
 */
export function renamePublicSecret(oldName: string): Codemod {
  const newName = oldName.replace(/^(NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_|PUBLIC_)/, "");
  if (newName === oldName) return () => null;

  return ({ path, content }) => {
    if (!content.includes(oldName)) return null;
    // Word-boundary replace so NEXT_PUBLIC_API_KEY_ID is not caught by
    // NEXT_PUBLIC_API_KEY.
    const re = new RegExp(`\\b${oldName}\\b`, "g");
    const next = content.replace(re, newName);
    // A substring match is not an occurrence: `includes` is true for
    // NEXT_PUBLIC_API_KEY inside NEXT_PUBLIC_API_KEY_ID, but the bounded replace
    // correctly changes nothing. Report that as "no codemod" rather than a
    // result whose diff is empty.
    if (next === content) return null;
    return {
      path,
      content: next,
      description: `rename ${oldName} to ${newName} so it is no longer inlined into the browser bundle`,
    };
  };
}

// ── Production source maps ─────────────────────────────────────────────────

/** Turns off `productionBrowserSourceMaps` when it has been explicitly enabled. */
export const disableProductionSourceMaps: Codemod = ({ path, content }) => {
  if (!/next\.config\.(ts|js|mjs)$/.test(path)) return null;
  if (!/productionBrowserSourceMaps\s*:\s*true/.test(content)) return null;
  return {
    path,
    content: content.replace(/productionBrowserSourceMaps\s*:\s*true/, "productionBrowserSourceMaps: false"),
    description: "stop publishing browser source maps in production builds",
  };
};


// ── Workflow permissions ───────────────────────────────────────────────────

/**
 * Adds `permissions: contents: read` to a workflow that declares none.
 *
 * Mechanical, and we applied this exact change to our own workflow by hand after
 * the C20 check flagged it — which is the test of whether a fix belongs here.
 * Inserted before `jobs:` at top level, which is where the YAML spec puts it and
 * where a human would.
 */
export const addWorkflowPermissions: Codemod = ({ path, content }) => {
  if (!/^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)) return null;
  // Already declared, at workflow or job level — leave it alone.
  if (/^permissions:/m.test(content) || /^\s+permissions:/m.test(content)) return null;

  const jobsAt = /^jobs:\s*$/m.exec(content);
  if (!jobsAt) return null;

  const block =
    "# Added by ShipLock: state what this workflow may do, rather than inheriting\n" +
    "# whatever the repository default happens to be. If a step later needs write\n" +
    "# access, this makes it fail loudly instead of silently having it.\n" +
    "permissions:\n  contents: read\n\n";

  return {
    path,
    content: content.slice(0, jobsAt.index) + block + content.slice(jobsAt.index),
    description: "declare least-privilege permissions on the workflow",
  };
};

// ── .gitignore a committed dotenv file ─────────────────────────────────────

/**
 * Adds the committed env file to .gitignore.
 *
 * Deliberately does NOT delete the file, and the PR body says why: removing it
 * from the working tree does not remove it from history, so the credential still
 * needs rotating either way. Deleting it would LOOK like the fix and would be the
 * most dangerous possible outcome — the developer stops worrying and the key is
 * still live and still reachable.
 */
export function gitignoreEnvFile(envPath: string): Codemod {
  return ({ path, content }) => {
    if (path !== ".gitignore") return null;
    const entry = envPath.split("/").pop() ?? envPath;
    const lines = content.split("\n").map((l) => l.trim());
    if (lines.includes(entry) || lines.includes(envPath) || lines.includes(".env*")) return null;

    const suffix = content.endsWith("\n") || content === "" ? "" : "\n";
    return {
      path,
      content: `${content}${suffix}\n# Added by ShipLock — this file was committed.\n${envPath}\n`,
      description: `add ${envPath} to .gitignore so it stops being committed`,
    };
  };
}

// ── Remove a logged secret ─────────────────────────────────────────────────

const LOGS_A_SECRET =
  /^\s*(?:console\.(?:log|error|warn|info|debug)|logger\.\w+)\s*\([^)]*\b(password|passwd|secret|token|access_?token|refresh_?token|api_?key|apiKey|authorization|cookie|private_?key|privateKey|service_?role|serviceRole)\b[^)]*\)\s*;?\s*$/i;

/**
 * Deletes a log statement that prints a credential.
 *
 * Mechanical because the correct output is "the line is gone" — there is no
 * judgement about what the app should do instead. Only removes lines that are
 * ENTIRELY a log call, so a log embedded in a larger expression is left for a
 * human rather than half-edited.
 */
export const removeSecretLogging: Codemod = ({ path, content }) => {
  if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(path)) return null;

  const lines = content.split("\n");
  const kept = lines.filter((line) => !LOGS_A_SECRET.test(line));
  if (kept.length === lines.length) return null;

  return {
    path,
    content: kept.join("\n"),
    description: `remove ${lines.length - kept.length} log statement${lines.length - kept.length === 1 ? "" : "s"} that printed a credential`,
  };
};

// ── Dispatch ───────────────────────────────────────────────────────────────

/**
 * The codemod for a finding, or null when the fix needs a human.
 *
 * Null is the common and correct answer. Most findings — injection, XSS,
 * ownership checks, tenant isolation — depend on what the application means to
 * do, and this returning null is what routes them to a draft PR where a person
 * decides.
 */
export function codemodFor(finding: FixableFinding): Codemod | null {
  const id = finding.id.includes("::") ? finding.id.slice(finding.id.indexOf("::") + 2) : finding.id;

  if (id.startsWith("scan:") && /security header/i.test(finding.title)) return addSecurityHeaders;
  if (id.startsWith("bundle:source_map_exposed")) return disableProductionSourceMaps;
  if (id.startsWith("github:workflow_no_permissions:")) return addWorkflowPermissions;
  if (id.startsWith("github:logged_secret")) return removeSecretLogging;

  const committedEnv = /^github:committed_env:(.+)$/.exec(id);
  if (committedEnv) return gitignoreEnvFile(committedEnv[1]);

  const publicSecret = /^github:public_prefixed_secret(?:_value)?:([A-Z0-9_]+):/.exec(id);
  if (publicSecret) return renamePublicSecret(publicSecret[1]);

  return null;
}

/** True when we can produce a real diff rather than instructions. */
export function hasCodemod(finding: FixableFinding): boolean {
  return codemodFor(finding) !== null;
}

/**
 * Runs the codemod across candidate files.
 *
 * Returns every file it changed. An empty result means the transform did not
 * find what it expected — reported as "no change" rather than committing a
 * partial edit, because a half-applied codemod is worse than none.
 */
export function applyCodemod(
  finding: FixableFinding,
  files: CodemodInput[]
): { results: CodemodResult[]; description: string } {
  const mod = codemodFor(finding);
  if (!mod) return { results: [], description: "" };

  const results: CodemodResult[] = [];
  for (const file of files) {
    const out = mod(file, finding);
    if (out && out.content !== file.content) results.push(out);
  }

  return { results, description: results[0]?.description ?? "" };
}
