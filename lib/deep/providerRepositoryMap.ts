import { getSupabaseAdmin } from "@/lib/supabase";
import { createHash, randomBytes } from "node:crypto";
import type { VercelProject } from "./vercel";

interface SelectedRepository {
  id: string;
  full_name: string;
  github_repo_id: number | string | null;
}

/**
 * A new opaque connection epoch (Step 2D, migration 067). Minted only on a
 * true connect/reconnect and cleared on disconnect; a token refresh or
 * re-encryption keeps the current one, so it never invalidates evidence.
 */
export function newConnectionEpoch(): string {
  return randomBytes(32).toString("hex");
}

/** Opaque identity of this installation, never a plaintext credential. */
export function providerConnectionFingerprint(encryptedToken: string): string {
  return createHash("sha256").update(encryptedToken).digest("hex");
}

/**
 * Persist associations Vercel itself proves through a GitHub project link.
 * Names are compared only as provider-issued repository identities, never by
 * similarity. If both sides carry GitHub's numeric id, an id mismatch rejects
 * the association even when the display name matches.
 */
export async function syncVercelRepositoryLinks(
  userId: string,
  projects: VercelProject[],
  encryptedToken: string,
): Promise<Map<string, string>> {
  const admin = getSupabaseAdmin();
  const { data, error } = await admin
    .from("repositories")
    .select("id, full_name, github_repo_id")
    .eq("user_id", userId)
    .eq("selected", true);
  if (error) throw new Error(`Selected repositories could not be read: ${error.message}`);

  const repositories = (data ?? []) as SelectedRepository[];
  const byName = new Map<string, SelectedRepository>();
  const ambiguous = new Set<string>();
  for (const repo of repositories) {
    const name = repo.full_name.toLowerCase();
    if (byName.has(name)) ambiguous.add(name);
    byName.set(name, repo);
  }
  const associations = new Map<string, string>();
  const rows: Array<Record<string, unknown>> = [];

  for (const project of projects) {
    const link = project.gitRepository;
    if (!link) continue;
    if (ambiguous.has(link.fullName.toLowerCase())) continue;
    const repository = byName.get(link.fullName.toLowerCase());
    if (!repository) continue;

    const storedGithubId = repository.github_repo_id == null ? null : String(repository.github_repo_id);
    if (link.repoId && storedGithubId && link.repoId !== storedGithubId) continue;

    associations.set(project.id, repository.id);
    rows.push({
      user_id: userId,
      provider: "vercel",
      provider_project_id: project.id,
      provider_project_name: project.name,
      provider_repository: link.fullName,
      provider_repository_id: link.repoId,
      repository_id: repository.id,
      verification_method: "provider_git_link",
      connection_fingerprint: providerConnectionFingerprint(encryptedToken),
      verified_at: new Date().toISOString(),
    });
  }

  if (rows.length > 0) {
    const { error: writeError } = await admin
      .from("provider_repository_links")
      .upsert(rows, { onConflict: "user_id,provider,provider_project_id" });
    if (writeError) throw new Error(`Provider repository links could not be saved: ${writeError.message}`);
  }

  // A currently observed project that no longer has a valid Git link must not
  // keep an older association. Unobserved projects are left alone because the
  // upstream list is paginated and absence is not proof of removal.
  const unmappedObserved = projects
    .map((project) => project.id)
    .filter((projectId) => !associations.has(projectId));
  if (unmappedObserved.length > 0) {
    const { error: deleteError } = await admin
      .from("provider_repository_links")
      .delete()
      .eq("user_id", userId)
      .eq("provider", "vercel")
      .in("provider_project_id", unmappedObserved);
    if (deleteError) throw new Error(`Stale provider repository links could not be cleared: ${deleteError.message}`);
  }

  return associations;
}

/** Project/installation identities admitted for a currently selected repo. */
export async function loadVerifiedProviderProjects(
  userId: string,
  repositoryId: string,
): Promise<Set<string>> {
  const admin = getSupabaseAdmin();
  const [{ data: profile, error: profileError }, { data: repository, error: repositoryError }] = await Promise.all([
    admin.from("user_profiles").select("vercel_access_token_encrypted").eq("id", userId).maybeSingle(),
    admin.from("repositories").select("id").eq("user_id", userId)
      .eq("id", repositoryId).eq("selected", true).maybeSingle(),
  ]);
  if (profileError || repositoryError) throw new Error("Current provider authorization could not be read");
  if (!repository || !profile?.vercel_access_token_encrypted) return new Set();
  const fingerprint = providerConnectionFingerprint(profile.vercel_access_token_encrypted);
  const { data, error } = await admin
    .from("provider_repository_links")
    .select("provider, provider_project_id, connection_fingerprint")
    .eq("user_id", userId)
    .eq("repository_id", repositoryId);
  if (error) throw new Error(`Provider repository links could not be read: ${error.message}`);
  return new Set(
    (data ?? []).filter((row) => row.provider === "vercel" && row.connection_fingerprint === fingerprint)
      .map((row) => `vercel:${String(row.provider_project_id)}:${fingerprint}`),
  );
}
