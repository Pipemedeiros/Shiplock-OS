import { createHash, randomBytes } from "node:crypto";

export const GITHUB_INSTALL_COOKIE = "shiplock_github_install";
export const GITHUB_INSTALL_TTL_SECONDS = 10 * 60;

export function newGithubInstallNonce(): string {
  return randomBytes(32).toString("hex");
}

export function hashGithubInstallNonce(nonce: string): string {
  return createHash("sha256").update(nonce, "utf8").digest("hex");
}
