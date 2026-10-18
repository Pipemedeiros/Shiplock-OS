import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken } from "@/lib/deep/github";
import { assertPublicHttpsUrl } from "@/lib/security/ssrfGuard";
import { z } from "zod";
import { suggestAppUrl } from "./appUrl";
import type { CertificateName } from "@/lib/security/certificateNames";

/**
 * The founder's app address, read by the outside view (lib/security/
 * exposedPathsRun.ts) through the app-surface collector. Suggested from the
 * selected repositories' GitHub homepages; set only on the founder's confirm.
 * The confirm may name the selected repository the address serves (P5): the
 * binding keeps the address it was confirmed for, so a later change of
 * address by any writer ends the join (lib/chain/liveReach.ts).
 */
/** A repository's homepage from GitHub (metadata read, no new permission).
 * Read here rather than in lib/deep/github.ts, which is a pinned PR writer. */
export async function repoHomepage(token: string, fullName: string): Promise<string | null> {
  const res = await fetch(`https://api.github.com/repos/${fullName}`, {
    headers: { Accept: "application/vnd.github+json", Authorization: `token ${token}`, "X-GitHub-Api-Version": "2022-11-28" },
    signal: AbortSignal.timeout(8_000),
  });
  if (!res.ok) return null;
  const json = (await res.json()) as { homepage?: unknown };
  return typeof json.homepage === "string" && json.homepage.trim() ? json.homepage.trim() : null;
}

export type AppUrlState = {
  current: string | null;
  /** The selected repository the current address was confirmed for, if any. */
  repository: string | null;
  /** Selected repositories the founder may name when confirming. */
  repositories: string[];
  /** Other names under the domain from certificate transparency, read for the
   * current address; null when not read (or read for another address). */
  otherNames: CertificateName[] | null;
  suggestions: { repository: string; url: string }[];
};

type Selected = { id: string; full_name: string };

const Names = z.array(z.object({ name: z.string().regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/).max(253),
  lastIssued: z.string().regex(/^\d{4}-\d{2}-\d{2}$/) })).max(50);

/** The last read's other names, only when it was read from the current address. */
async function otherNamesFor(userId: string, current: string | null): Promise<CertificateName[] | null> {
  if (!current) return null;
  const { data } = await getSupabaseAdmin().from("graph_facts").select("facts").eq("user_id", userId).eq("collector", "runtime").maybeSingle();
  const surface = (data?.facts as { appSurface?: { url?: unknown; certificateNames?: unknown } } | undefined)?.appSurface;
  if (!surface || surface.url !== current) return null;
  const parsed = Names.safeParse(surface.certificateNames);
  return parsed.success ? parsed.data : null;
}

export async function getAppUrlState(userId: string): Promise<AppUrlState> {
  const admin = getSupabaseAdmin();
  const { data: profile } = await admin.from("user_profiles")
    .select("github_installation_id, monitored_app_url, monitored_app_repository_id, monitored_app_bound_url").eq("id", userId).maybeSingle();
  const current = (profile?.monitored_app_url as string | null) ?? null;
  const otherNames = await otherNamesFor(userId, current).catch(() => null);
  const installation = profile?.github_installation_id as number | string | null | undefined;
  if (!installation) return { current, repository: null, repositories: [], otherNames, suggestions: [] };
  const { data: rows } = await admin.from("repositories").select("id, full_name").eq("user_id", userId).eq("selected", true);
  const selected = (rows ?? []) as Selected[];
  const names = [...new Set(selected.map((r) => r.full_name))].slice(0, 10);
  const bound = current && profile?.monitored_app_bound_url === current
    ? selected.find((r) => r.id === profile?.monitored_app_repository_id)?.full_name ?? null : null;
  const base = { current, repository: bound, repositories: names, otherNames };
  try {
    const token = await getInstallationToken(installation);
    const homepages = await Promise.all(names.map(async (fullName) => ({ fullName, homepage: await repoHomepage(token, fullName).catch(() => null) })));
    const suggestions = homepages
      .map((r) => ({ repository: r.fullName, url: suggestAppUrl(r.homepage) }))
      .filter((s): s is { repository: string; url: string } => s.url !== null && s.url !== current);
    return { ...base, suggestions };
  } catch {
    // A suggestion is a convenience; an unreadable GitHub must not hide the address.
    return { ...base, suggestions: [] };
  }
}

/** Saves the origin of a public https address; throws invalid_url otherwise.
 * A named repository must be selected for this account (invalid_repository). */
export async function setAppUrl(userId: string, value: string, repository: string | null = null): Promise<string> {
  let origin: string;
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "https:" || url.username || url.password || !url.hostname.includes(".")) throw new Error("shape");
    origin = url.origin;
    await assertPublicHttpsUrl(origin);
  } catch {
    throw new Error("invalid_url");
  }
  let repositoryId: string | null = null;
  if (repository) {
    const { data } = await getSupabaseAdmin().from("repositories").select("id")
      .eq("user_id", userId).eq("full_name", repository).eq("selected", true).maybeSingle();
    repositoryId = (data as { id?: string } | null)?.id ?? null;
    if (!repositoryId) throw new Error("invalid_repository");
  }
  const { error } = await getSupabaseAdmin().from("user_profiles").update({ monitored_app_url: origin,
    monitored_app_repository_id: repositoryId, monitored_app_bound_url: repositoryId ? origin : null }).eq("id", userId);
  if (error) throw new Error("app_url_unsaved");
  return origin;
}

export async function clearAppUrl(userId: string): Promise<void> {
  const { error } = await getSupabaseAdmin().from("user_profiles")
    .update({ monitored_app_url: null, monitored_app_repository_id: null, monitored_app_bound_url: null }).eq("id", userId);
  if (error) throw new Error("app_url_unsaved");
}
