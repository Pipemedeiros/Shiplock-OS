import { scanSecrets, type RepoFile } from "@/lib/deep/githubScan";
import { scanNextConfigEnv } from "@/lib/deep/nextConfigEnv";
import { scanPublicCredentialValues } from "@/lib/deep/clientExposure";
import { scanCredentialHandling } from "@/lib/deep/credentialHandling";

/**
 * The checks an audit runs on the repository with no agent and no model:
 * committed credentials and configuration exposure. Shared by the audit and
 * the offline harness (`scripts/corpus.cjs shown`), so a measurement of what a
 * founder sees is a measurement of production.
 */
export function deterministicFindings(files: RepoFile[]) {
  return [
    ...scanSecrets(files),
    ...scanNextConfigEnv(files),
    ...scanPublicCredentialValues(files),
    ...scanCredentialHandling(files),
  ];
}
