import type { GithubFinding } from "./githubScan";

// A12 / A13 — storage buckets and the policies on their objects.
//
// The existing scanner already finds a PUBLIC bucket from the outside (check 16,
// via the anon key) and lists secret-looking filenames in it. This covers what
// that view cannot see: a bucket that is private but whose object policies let
// anyone read it anyway, and the upload restrictions that decide what a user can
// put in it.
//
// The distinction matters because "private" in the Supabase dashboard means only
// that objects are not served over an unauthenticated URL. Access is still
// decided by RLS policies on storage.objects, and a permissive policy there
// makes a private bucket readable by anyone with the anon key — a state that
// looks correct in every place a founder would think to check.
//
// Upload restrictions are the other half. A bucket with no size limit and no MIME
// allow-list accepts anything of any size from anyone who can upload: that is a
// storage bill, a malware host on the customer's domain, and a stored-XSS vector
// if an uploaded .html or .svg is served back from the same origin.

const f = (
  id: string,
  severity: GithubFinding["severity"],
  title: string,
  consequence: string
): GithubFinding => ({
  id, severity, title, consequence,
  packageName: null, version: null, vulnId: null, cveId: null,
});

export const BUCKET_SQL = `
select id, name, public, file_size_limit, allowed_mime_types
from storage.buckets
order by name`;

export const STORAGE_POLICY_SQL = `
select policyname as name, cmd, coalesce(qual, '') as qual, array_to_string(roles, ',') as roles
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by policyname`;

export interface BucketRow {
  id: string;
  name: string;
  public: boolean;
  file_size_limit: number | null;
  allowed_mime_types: string[] | null;
}

export interface StoragePolicyRow {
  name: string;
  cmd: string;
  qual: string;
  roles: string;
}

/** A policy expression that filters nothing. */
function filtersNothing(qual: string): boolean {
  const normalised = qual.trim().toLowerCase().replace(/\s+/g, " ").replace(/^\(+|\)+$/g, "");
  return normalised === "true" || normalised === "1=1";
}

/** Roles a browser can act as with a public key. */
function isPublicRole(roles: string): boolean {
  return /\b(anon|public|authenticated)\b/.test(roles);
}

/**
 * A12 — a private bucket whose object policies grant unconditional read.
 *
 * The combination is the finding. A permissive policy on a bucket that is ALREADY
 * public tells the customer nothing new — check 16 reports that from the outside,
 * and repeating it here would be the same problem twice on one board.
 */
export function checkObjectPolicies(
  buckets: BucketRow[],
  policies: StoragePolicyRow[]
): GithubFinding[] {
  const permissive = policies.filter(
    (p) => filtersNothing(p.qual) && isPublicRole(p.roles) && /select|all/i.test(p.cmd)
  );
  if (permissive.length === 0) return [];

  const privateBuckets = buckets.filter((b) => !b.public);
  // Nothing private to expose means nothing new to say.
  if (privateBuckets.length === 0) return [];

  return [
    f(
      "storage:permissive_object_policy",
      "CRITICAL",
      `Your private storage buckets are readable by anyone`,
      `A policy on storage.objects (${permissive.map((p) => p.name).join(", ")}) grants read access unconditionally to ${permissive[0].roles}. ` +
        `You have ${privateBuckets.length} bucket${privateBuckets.length === 1 ? "" : "s"} marked private: ${privateBuckets.map((b) => b.name).join(", ")}, and that setting is not what decides access. Marking a bucket private only stops objects being served from an unauthenticated URL; who may read them is decided by these policies, and this one says everyone. ` +
        `So the files are reachable by anyone holding your public key, while every place you would look to check (the bucket list, the dashboard) shows "private". ` +
        `Fix: scope the policy to the owner, e.g. \`using (auth.uid()::text = (storage.foldername(name))[1])\`, or restrict it to the specific bucket it was written for.`
    ),
  ];
}

/**
 * A13 — upload restrictions.
 *
 * Only reported for buckets that are public or have a permissive read path,
 * because an unrestricted PRIVATE bucket that only the owner can touch is a
 * capacity question rather than a security one, and we are not a billing alert.
 */
export function checkUploadLimits(buckets: BucketRow[], anyPermissivePolicy: boolean): GithubFinding[] {
  const out: GithubFinding[] = [];

  for (const bucket of buckets) {
    const reachable = bucket.public || anyPermissivePolicy;
    if (!reachable) continue;

    const noSize = bucket.file_size_limit === null;
    const noMime = !bucket.allowed_mime_types || bucket.allowed_mime_types.length === 0;
    if (!noSize && !noMime) continue;

    const missing = [noSize ? "no size limit" : null, noMime ? "no file-type restriction" : null]
      .filter(Boolean)
      .join(" and ");

    out.push(
      f(
        `storage:unrestricted_uploads:${bucket.name}`,
        noMime ? "WARNING" : "INFO",
        `The ${bucket.name} bucket accepts uploads with ${missing}`,
        `${bucket.name} is reachable ${bucket.public ? "publicly" : "through a permissive policy"} and has ${missing}. ` +
          (noMime
            ? `Without a MIME allow-list it accepts any file type. Two consequences that are easy to miss: your domain becomes a place to host other people's files (malware served from your name, with your reputation behind it) and an uploaded .html or .svg served back from your origin runs as script on your site, which is stored XSS with a permanent home. ` +
              `Set \`allowed_mime_types\` to the formats you actually accept. If it is images, say images; the check is one line and it removes the whole class.`
            : `Without a size limit a single upload can be as large as the caller wants, which is a storage bill rather than a breach: worth setting because nothing else will stop it.`)
      )
    );
  }

  return out;
}

export interface StorageInput {
  buckets?: BucketRow[];
  policies?: StoragePolicyRow[];
}

/** Both storage checks. Absent input means we could not look. */
export function scanStorage(input: StorageInput): GithubFinding[] {
  if (!input.buckets) return [];
  const policies = input.policies ?? [];

  const anyPermissive = policies.some(
    (p) => filtersNothing(p.qual) && isPublicRole(p.roles) && /select|all/i.test(p.cmd)
  );

  return [
    ...(input.policies ? checkObjectPolicies(input.buckets, policies) : []),
    ...checkUploadLimits(input.buckets, anyPermissive),
  ];
}

/**
 * A19 — recovery posture.
 *
 * `null` means we could not read it, which very often means the plan does not
 * offer PITR at all. "Not available on your plan" is not a security finding, and
 * reporting one would be telling a customer to buy something to satisfy us.
 */
export function checkBackups(config: { pitrEnabled: boolean; walgEnabled: boolean } | null): GithubFinding[] {
  if (!config) return [];
  if (config.pitrEnabled) return [];

  return [
    f(
      "storage:no_pitr",
      "INFO",
      "Point-in-time recovery is off",
      "Your project keeps daily backups but not point-in-time recovery, so the most you can lose to a bad migration, a mistaken delete, or ransomware is a day of data, and you can only return to the backup boundary, not to the moment before it happened. " +
        "This is a note, not a vulnerability, and it is genuinely a cost decision rather than a security one. It is here because the scenario people underestimate is not an attacker: it is a `delete` that ran without its `where` clause, where the difference between losing a day and losing four minutes is whether this was on beforehand.",
    ),
  ];
}
