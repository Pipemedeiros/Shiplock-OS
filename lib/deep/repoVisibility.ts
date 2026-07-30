import type { GithubFinding } from "./githubScan";

// C22 from CHECK-SPEC.md — a repository that is public when it shouldn't be.
//
// On its own, a public repo is NOT a vulnerability. Plenty of people open-source
// deliberately, and a scanner that shouts about it looks like it doesn't
// understand software. So this check refuses to treat visibility as a finding in
// isolation.
//
// What makes it matter is the correlation. Every secret we already found in that
// repo has a completely different blast radius depending on this one boolean:
//   private  -> readable by the customer's collaborators
//   public   -> readable by anyone, indexed by search engines, mirrored by
//               scraping bots, and PRESENT IN GIT HISTORY FOREVER even after the
//               file is deleted
// Credential-harvesting bots scan newly-pushed public commits continuously, so
// for a public repo the honest assumption is not "this could leak" but "this has
// already been collected". That changes the instruction from "remove it" to
// "rotate it now, removal is not enough".
//
// This is the graph paying for itself: two facts we already have, neither
// alarming alone, that together identify a time-critical problem.

/**
 * Finding ids whose danger is multiplied by public visibility. All of them mean
 * "a credential is sitting in this repository".
 */
const SECRET_FINDING_PREFIXES = [
  "github:secret:",
  "github:committed_env:",
  "github:client_server_secret:",
  "github:public_prefixed_secret",
];

export function isSecretFinding(id: string): boolean {
  return SECRET_FINDING_PREFIXES.some((prefix) => id.startsWith(prefix));
}

export interface RepoVisibility {
  fullName: string;
  isPrivate: boolean | null;
  visibility: string | null;
}

/**
 * @param repo         visibility metadata from listRepos
 * @param repoFindings findings already produced for THIS repo, used to decide
 *                     whether public visibility is currently dangerous
 */
export function checkRepoVisibility(repo: RepoVisibility, repoFindings: GithubFinding[]): GithubFinding[] {
  // `null` means GitHub didn't tell us. Unknown must never become an alarm — a
  // missing field is not evidence of a public repo.
  if (repo.isPrivate !== false) return [];

  // "internal" is an enterprise visibility: org members only, not the world.
  if (repo.visibility === "internal") return [];

  const leaked = repoFindings.filter((finding) => isSecretFinding(finding.id));

  if (leaked.length === 0) {
    return [
      {
        id: `github:repo_public:${repo.fullName}`,
        severity: "WARNING",
        title: `${repo.fullName} is a public repository`,
        consequence:
          `${repo.fullName} is readable by anyone on the internet, including its full commit history. ` +
          `If that's deliberate, nothing here needs doing and you can ignore this. ` +
          `We flag it because it changes what a mistake costs: from now on, any credential committed to this repo is public the moment you push, ` +
          `and deleting the file afterwards does not remove it from history. ` +
          `Credential-harvesting bots watch new public commits continuously — the window between pushing a key and it being used is minutes, not days. ` +
          `We check every pull request, so if a secret does land here you'll hear from us immediately.`,
        packageName: null,
        version: null,
        vulnId: null,
        cveId: null,
      },
    ];
  }

  return [
    {
      id: `github:repo_public_with_secrets:${repo.fullName}`,
      severity: "CRITICAL",
      title: `${repo.fullName} is PUBLIC and contains ${leaked.length} exposed credential${leaked.length === 1 ? "" : "s"}`,
      consequence:
        `${repo.fullName} is readable by anyone on the internet, and we found ${leaked.length} credential${leaked.length === 1 ? "" : "s"} committed to it: ` +
        `${leaked.map((finding) => finding.title).join("; ")}. ` +
        `Treat every one of these as already compromised rather than at risk. Bots scan newly-pushed public commits for exactly these patterns, so assume the keys have been collected. ` +
        `ROTATE them now — that is the only step that actually stops this. ` +
        `Deleting the files does not help: they remain in your commit history and stay readable forever. ` +
        `Making the repository private also does not help, because anything already fetched or forked is out of your control. ` +
        `Rotate first, then clean up, in that order.`,
      packageName: null,
      version: null,
      vulnId: null,
      cveId: null,
    },
  ];
}
