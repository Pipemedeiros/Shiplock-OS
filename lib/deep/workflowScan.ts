import { parse } from "yaml";
import type { GithubFinding, RepoFile } from "./githubScan";

// C20 — GitHub Actions workflow security.
//
// CI is a live attack path, and an under-appreciated one: a workflow runs with a
// token that can write to the repository, and usually with every secret the repo
// holds. Compromising a workflow is compromising the codebase and everything it
// deploys to — without touching the production database at all.
//
// It is also the one surface where "it's only our internal tooling" is most
// often said and least often true. A public repo's CI accepts input from anyone
// who can open a pull request or file an issue.
//
// PARSED, NOT PATTERN-MATCHED. These checks depend on YAML STRUCTURE — whether a
// `${{ }}` expression sits inside a `run:` block or a `with:` value changes it
// from a shell injection into an ordinary parameter, and no regex distinguishes
// those reliably. Having shipped one check this week that ran at a 100%
// false-positive rate because it guessed from text, the parser is worth its
// weight.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

export function isWorkflowFile(path: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path);
}

interface Step {
  uses?: unknown;
  run?: unknown;
  with?: Record<string, unknown>;
  env?: Record<string, unknown>;
}
interface Job {
  steps?: Step[];
  permissions?: unknown;
}
interface Workflow {
  on?: unknown;
  permissions?: unknown;
  jobs?: Record<string, Job>;
}

function parseWorkflow(content: string): Workflow | null {
  try {
    const doc = parse(content) as unknown;
    return doc && typeof doc === "object" ? (doc as Workflow) : null;
  } catch {
    // A workflow we cannot parse is one we know nothing about. Unknown is never
    // a finding.
    return null;
  }
}

/** Every trigger name, whether `on` is a string, array, or map. */
export function triggerNames(on: unknown): string[] {
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.filter((t): t is string => typeof t === "string");
  if (on && typeof on === "object") return Object.keys(on as Record<string, unknown>);
  return [];
}

function steps(workflow: Workflow): { job: string; step: Step }[] {
  const out: { job: string; step: Step }[] = [];
  for (const [job, def] of Object.entries(workflow.jobs ?? {})) {
    for (const step of def?.steps ?? []) {
      if (step && typeof step === "object") out.push({ job, step });
    }
  }
  return out;
}

// Contexts an outsider controls. `github.event.*` is the big one: PR titles,
// branch names, issue bodies and commit messages are all attacker-writable on a
// public repo.
const UNTRUSTED_EXPR =
  /\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|discussion|head_commit|commits)|github\.head_ref|github\.event\.inputs)[^}]*\}\}/;

/**
 * The classic pull_request_target RCE.
 *
 * `pull_request_target` runs with the BASE repository's token and secrets — that
 * is its purpose, so a fork PR can be labelled or commented on. Checking out the
 * PR's own head inside that context executes an outsider's code with those
 * privileges. It is the single most exploited GitHub Actions mistake.
 */
export function checkPullRequestTarget(path: string, workflow: Workflow): GithubFinding[] {
  if (!triggerNames(workflow.on).includes("pull_request_target")) return [];

  const checkoutsPrHead = steps(workflow).some(({ step }) => {
    if (typeof step.uses !== "string" || !/actions\/checkout/.test(step.uses)) return false;
    const ref = step.with?.ref;
    return typeof ref === "string" && /github\.event\.pull_request\.head|github\.head_ref|merge/.test(ref);
  });
  if (!checkoutsPrHead) return [];

  return [
    f(
      `github:workflow_prtarget_rce:${path}`,
      "CRITICAL",
      `${path} runs untrusted pull-request code with your secrets`,
      `${path} triggers on \`pull_request_target\` and then checks out the pull request's own branch. ` +
        `Those two together are the most exploited mistake in GitHub Actions. \`pull_request_target\` deliberately runs with YOUR repository's token and YOUR secrets — that is what makes it useful for labelling or commenting on outside contributions — and checking out the contributor's branch then executes their code with all of it. ` +
        `Anyone who can open a pull request, including from a fork, can read every secret in this repository and push to it. They do not need it merged, or even reviewed. ` +
        `Fix: use \`pull_request\` instead, which runs without secrets, or keep \`pull_request_target\` and do NOT check out the PR head — only the base.`
    ),
  ];
}

/**
 * Script injection: an attacker-controlled string interpolated into a shell.
 *
 * `run: echo "${{ github.event.pull_request.title }}"` is a shell command built
 * by string substitution, so a title containing a backtick or `$( )` executes.
 * Only `run:` blocks are affected — the same expression in `with:` is a
 * parameter, not a command, which is exactly why this needs the parser.
 */
export function checkScriptInjection(path: string, workflow: Workflow): GithubFinding[] {
  const hits = steps(workflow).filter(
    ({ step }) => typeof step.run === "string" && UNTRUSTED_EXPR.test(step.run)
  );
  if (hits.length === 0) return [];

  return [
    f(
      `github:workflow_script_injection:${path}`,
      "CRITICAL",
      `${path} builds a shell command from text an outsider controls`,
      `A \`run:\` step in ${path} interpolates \`\${{ github.event... }}\` directly into a shell command. Those values — pull request titles, branch names, issue bodies, commit messages — are written by whoever opened them. ` +
        `Because the expression is substituted into the script before the shell sees it, a title containing a backtick or \`$(...)\` runs as a command, with the workflow's token and secrets. Nothing needs to be merged for this to fire. ` +
        `Fix: pass the value through the environment instead of interpolating it — set \`env: TITLE: \${{ github.event.pull_request.title }}\` and use \`"$TITLE"\` in the script. The shell then treats it as data, never as code.`
    ),
  ];
}

const SHA_PINNED = /@[0-9a-f]{40}$/i;
/** First-party actions are maintained by GitHub and conventionally tag-pinned. */
const FIRST_PARTY = /^(actions|github)\//i;

/**
 * Third-party actions pinned to a mutable ref.
 *
 * `@v3` and `@main` are tags and branches — the author can move them at any
 * time, and so can anyone who compromises the author's account. The npm
 * supply-chain worm on /incidents is the same shape of attack.
 */
export function checkUnpinnedActions(path: string, workflow: Workflow): GithubFinding[] {
  const unpinned = new Set<string>();

  for (const { step } of steps(workflow)) {
    if (typeof step.uses !== "string") continue;
    const uses = step.uses.trim();
    if (uses.startsWith("./") || uses.startsWith("docker://")) continue;
    if (FIRST_PARTY.test(uses)) continue;
    if (SHA_PINNED.test(uses)) continue;
    if (!uses.includes("@")) continue;
    unpinned.add(uses);
  }

  if (unpinned.size === 0) return [];

  return [
    f(
      `github:workflow_unpinned_action:${path}`,
      "WARNING",
      `${path} runs third-party actions from a moveable tag`,
      `${path} uses ${[...unpinned].sort().join(", ")}, pinned to a tag or branch rather than a commit. ` +
        `Tags are not immutable: the author can repoint one at new code at any time, and so can anyone who takes over their account. Your CI then runs that code with your repository token and secrets, on your next push, with nothing in your diff to show anything changed. ` +
        `This is the same shape as the npm supply-chain attacks — the compromise is upstream, and the victim's own code is untouched. ` +
        `Fix: pin to the full commit SHA (\`uses: owner/action@<40-char-sha>\`). Dependabot updates SHA pins for you, so this costs nothing ongoing. First-party \`actions/*\` are not flagged here.`
    ),
  ];
}

/**
 * Workflow-level `permissions` left at the default.
 *
 * Reported at INFO, not higher, because on repositories created since 2023 the
 * default is already read-only, so this is frequently a non-issue — and saying
 * so is more useful than implying a problem we cannot confirm from the file.
 */
export function checkPermissions(path: string, workflow: Workflow): GithubFinding[] {
  if (workflow.permissions !== undefined) return [];
  const jobsDeclare = Object.values(workflow.jobs ?? {}).every((j) => j?.permissions !== undefined);
  if (jobsDeclare && Object.keys(workflow.jobs ?? {}).length > 0) return [];

  return [
    f(
      `github:workflow_no_permissions:${path}`,
      "INFO",
      `${path} does not state what it is allowed to do`,
      `${path} declares no \`permissions:\` block, so its token gets whatever the repository default is. On repositories created in the last couple of years that default is read-only and this is nothing to worry about; on older ones it is write-all, meaning any compromise of this workflow can push code. ` +
        `We cannot tell which from the file alone, which is why this is a note rather than a finding. ` +
        `Adding \`permissions: contents: read\` at the top makes it explicit and costs nothing — and if the workflow then fails, it was relying on write access you did not know it had.`
    ),
  ];
}

/** All workflow checks across every workflow file in the repo. */
export function scanWorkflows(files: RepoFile[]): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const file of files) {
    if (!isWorkflowFile(file.path)) continue;
    const workflow = parseWorkflow(file.content);
    if (!workflow) continue;

    out.push(
      ...checkPullRequestTarget(file.path, workflow),
      ...checkScriptInjection(file.path, workflow),
      ...checkUnpinnedActions(file.path, workflow),
      ...checkPermissions(file.path, workflow)
    );
  }

  return out;
}
