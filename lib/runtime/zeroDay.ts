import { queryOsv } from "@/lib/deep/github";
import { depFindings, type GithubFinding } from "@/lib/deep/githubScan";

interface RepositoryDependencyInventory {
  repositoryId: string;
  repositoryFullName: string;
  sourceRevision: string;
  dependencies: { name: string; version: string }[];
  completeness: "partial";
}

/** Historical helper retained for stable-id compatibility tests. */
export function stripRepoPrefix(id: string): string {
  const at = id.indexOf("::");
  return at === -1 ? id : id.slice(at + 2);
}

/** Read current advisories for one admitted repository inventory. Persistence,
 * deduplication, and lease fencing belong to the dependency worker/RPC. */
export async function collectDependencyFindings(
  inventory: RepositoryDependencyInventory,
): Promise<GithubFinding[]> {
  if (inventory.dependencies.length === 0) return [];
  const prefix = `${inventory.repositoryFullName}::`;
  return depFindings(await queryOsv(inventory.dependencies)).map((finding) => ({
    ...finding,
    id: prefix + finding.id,
    consequence: `${finding.consequence}\n\nFound by re-checking recorded dependencies for ${inventory.repositoryFullName}. `
      + "It closes when that lockfile is read again and no longer installs this version; an advisory feed going quiet never closes it.",
  }));
}
