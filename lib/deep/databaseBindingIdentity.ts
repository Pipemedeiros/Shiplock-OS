import { z } from "zod";
import { getSupabaseAdmin } from "@/lib/supabase";

export const bindingNumericId = z.union([z.string().regex(/^[1-9]\d*$/), z.number().int().positive().max(Number.MAX_SAFE_INTEGER)]).transform(String);
export const bindingDate = z.iso.datetime({ offset: true }).transform((value) => new Date(value).toISOString());
export const bindingRepositorySchema = z.object({ id: z.uuid(), full_name: z.string().regex(/^[\w.-]+\/[\w.-]+$/),
  github_repo_id: bindingNumericId.nullable() });
const githubProfile = z.object({ github_installation_id: bindingNumericId, github_connected_at: bindingDate }).passthrough();

/** Shared server-only identity read for customer decisions. Column selections
 * are fixed by server callers, never supplied by HTTP input. Profile context
 * can include ciphertext; callers must never serialize it to the customer. */
export async function loadDatabaseBindingIdentity(userId: string, profileColumns: string, now = Date.now()) {
  const admin = getSupabaseAdmin();
  const [profileRead, repositoriesRead] = await Promise.all([
    admin.from("user_profiles").select(`${profileColumns}, github_installation_id, github_connected_at`).eq("id", userId).maybeSingle(),
    admin.from("repositories").select("id, full_name, github_repo_id").eq("user_id", userId).eq("selected", true),
  ]);
  if (profileRead.error || repositoriesRead.error) throw new Error("Binding context unavailable");
  const profile = githubProfile.safeParse(profileRead.data);
  const repositories = z.array(bindingRepositorySchema).safeParse(repositoriesRead.data);
  if (!profile.success || !repositories.success || !Number.isFinite(now) || Date.parse(profile.data.github_connected_at) > now) return null;
  const ids = new Map<string, number>(), names = new Map<string, number>(), githubIds = new Map<string, number>();
  for (const repository of repositories.data) {
    ids.set(repository.id, (ids.get(repository.id) ?? 0) + 1);
    const name = repository.full_name.toLowerCase(); names.set(name, (names.get(name) ?? 0) + 1);
    if (repository.github_repo_id) githubIds.set(repository.github_repo_id, (githubIds.get(repository.github_repo_id) ?? 0) + 1);
  }
  return { profile: profile.data, repositories: repositories.data.filter((repository) =>
    ids.get(repository.id) === 1 && names.get(repository.full_name.toLowerCase()) === 1 &&
    (!repository.github_repo_id || githubIds.get(repository.github_repo_id) === 1)) };
}
