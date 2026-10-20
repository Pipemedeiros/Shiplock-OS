import type { RepositoryDeploy } from "@/lib/graph/repositorySource";

const utc = (iso: string) => iso.slice(0, 16).replace("T", " ") + " UTC";
const short = (sha: string) => sha.slice(0, 7);
const plural = (n: number) => n === 1 ? "1 commit ahead of it, so it is" : `${n} commits ahead of it, so they are`;

/**
 * Is it live? What production runs against the default branch, from the
 * deploys the host reports to GitHub (lib/deep/productionDeploy.ts). A merged
 * fix is not a deployed fix; unread or unknown is said as such.
 */
export function productionLine(stored: RepositoryDeploy | null): string {
  if (!stored) return "What production runs has not been checked yet.";
  const { deploy, ref } = stored;
  if (deploy.state === "unreadable") return `What is live is unknown. ${deploy.why}`;
  if (deploy.state === "none") return "Your host reports no production deploys to GitHub, so what is live is unknown.";
  const { live, latest, behindBy, host } = deploy;
  if (!live) return `No production deploy has succeeded in the deploys GitHub lists; the newest, of ${short(latest.sha)}, is ${latest.state.replace("_", " ")}.`;
  const runs = `Production runs ${short(live.sha)}`;
  const where = ` (${[host, utc(live.at)].filter(Boolean).join(", ")})`;
  const newer = latest.sha !== live.sha
    ? ["failure", "error"].includes(latest.state) ? `The newest production deploy, of ${short(latest.sha)}, failed. `
      : ["in_progress", "queued", "pending"].includes(latest.state) ? `A production deploy of ${short(latest.sha)} is running. ` : ""
    : "";
  if (behindBy === 0) return `${newer}${runs}, the head of ${ref}${where}.`;
  if (behindBy === null) return `${newer}${newer ? "Production still runs" : "Production runs"} ${short(live.sha)}${where}, but its history has diverged from ${ref}, so which of your commits are live is unknown.`;
  return `${newer}${newer ? "Production still runs" : "Production runs"} ${short(live.sha)}${where}. ${ref} is ${plural(behindBy)} not live.`;
}
