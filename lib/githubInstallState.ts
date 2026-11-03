import { createHash, randomBytes } from "node:crypto";

export const GITHUB_INSTALL_COOKIE = "shiplock_github_install";
export const GITHUB_INSTALL_TTL_SECONDS = 10 * 60;

/** A random nonce tying a GitHub App install back to the account that started
 * it. */
export function newGithubInstallNonce(): string {
  return randomBytes(32).toString("hex");
}

/** SHA-256 of the install nonce; only the hash is stored. */
export function hashGithubInstallNonce(nonce: string): string {
  return createHash("sha256").update(nonce, "utf8").digest("hex");
}
