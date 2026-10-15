import { getSupabaseAdmin } from "@/lib/supabase";
import { getInstallationToken } from "@/lib/deep/github";
import { assertPublicHttpsUrl } from "@/lib/security/ssrfGuard";
import { suggestAppUrl } from "./appUrl";

/**
 * The founder's app address, read by the outside view (lib/security/
 * exposedPathsRun.ts) through the app-surface collector. Suggested from the
 * selected repositories' GitHub homepages; set only on the founder's confirm.
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

export type AppUrlState = { current: string | null; suggestions: { repository: string; url: string }[] };

export async function getAppUrlState(userId: string): Promise<AppUrlState> {
  const admin = getSupabaseAdmin();
  const { data: profile } = await admin.from("user_profiles").select("github_installation_id, monitored_app_url").eq("id", userId).maybeSingle();
  const current = (profile?.monitored_app_url as string | null) ?? null;
  const installation = profile?.github_installation_id as number | string | null | undefined;
  if (!installation) return { current, suggestions: [] };
  try {
    const { data: selected } = await admin.from("repositories").select("full_name").eq("user_id", userId).eq("selected", true);
    const names = [...new Set(((selected ?? []) as { full_name: string }[]).map((r) => r.full_name))].slice(0, 10);
    const token = await getInstallationToken(installation);
    const homepages = await Promise.all(names.map(async (fullName) => ({ fullName, homepage: await repoHomepage(token, fullName).catch(() => null) })));
    const suggestions = homepages
      .map((r) => ({ repository: r.fullName, url: suggestAppUrl(r.homepage) }))
      .filter((s): s is { repository: string; url: string } => s.url !== null && s.url !== current);
    return { current, suggestions };
  } catch {
    // A suggestion is a convenience; an unreadable GitHub must not hide the address.
    return { current, suggestions: [] };
  }
}

/** Saves the origin of a public https address; throws invalid_url otherwise. */
export async function setAppUrl(userId: string, value: string): Promise<string> {
  let origin: string;
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "https:" || url.username || url.password || !url.hostname.includes(".")) throw new Error("shape");
    origin = url.origin;
    await assertPublicHttpsUrl(origin);
  } catch {
    throw new Error("invalid_url");
  }
  const { error } = await getSupabaseAdmin().from("user_profiles").update({ monitored_app_url: origin }).eq("id", userId);
  if (error) throw new Error("app_url_unsaved");
  return origin;
}

export async function clearAppUrl(userId: string): Promise<void> {
  const { error } = await getSupabaseAdmin().from("user_profiles").update({ monitored_app_url: null }).eq("id", userId);
  if (error) throw new Error("app_url_unsaved");
}
