/**
 * "Same write, weaker permission" (Step 7C-1). Deterministic, from source only.
 *
 * A Next.js App Router handler that declares its required permissions
 * (`requiredPermissions: ["links.write"]`) and writes a model is compared with
 * every other handler that writes the same model. If some other handler guards
 * that write with a permission named for the model's own resource
 * (`domains.write` for `prisma.domain.*`) and this handler holds no permission
 * for that resource, this handler reaches the write with a weaker permission.
 *
 * It is evidence, not a verdict: the repository's own rule is the witness, and
 * whether the weaker path is intended is the customer's business decision.
 * Conservative by construction:
 *   - a handler with no readable permission list is neither subject nor witness;
 *   - a handler with its own role check (`requiredRoles`, a `.role` comparison)
 *     is skipped, because that check may be the stronger gate;
 *   - no witness, no claim.
 *
 * Scope: only repositories that declare `requiredPermissions` lists. Role
 * checks written as code (`isOwnerOrManager`, `MembershipRole.ADMIN`,
 * `role !== "ADMIN"`) are NOT covered: an inferred rule over them was tried on
 * 2026-09-24 and flagged 5 public visitor-verification routes in corpus-b
 * that correctly have no role check (5 of 5 likely false), so it was dropped.
 *
 * Also reads Next.js Pages API handlers (`pages/api/**`), where the idiom is
 * a `const xHandler = withY(fn, { requiredPermissions: [...] })` per method,
 * dispatched from a `export default` function on `req.method`, or (less
 * often) one `export default withY(fn, { requiredPermissions })` branching on
 * `req.method` inline. The inline form is read only when exactly one method
 * appears in its body; more than one method sharing a single permission list
 * cannot be split into per-method writes without misattributing a read
 * branch's permission to a write in another branch, so it is left as neither
 * subject nor witness (2026-09-28, corpus-b: this is also how the one
 * inline multi-method handler in the pinned corpus already carries its own
 * code-level role check, so it is excluded either way).
 */
export type PermissionGap = {
  file: string;
  method: string;
  model: string;
  requires: string[];
  expected: string;
  witness: { file: string; method: string };
  tier: "declared";
};

type Handler = { file: string; method: string; permissions: string[]; writes: Set<string> };

const ROUTE_FILE = /(^|\/)app\/(.+\/)?route\.[cm]?[jt]sx?$/;
const PAGES_API_FILE = /(^|\/)pages\/api\/(.+\/)?[^/]+\.[cm]?[jt]sx?$/;
const EXPORT = /export\s+(?:const\s+(GET|POST|PUT|PATCH|DELETE)\s*=|async\s+function\s+(GET|POST|PUT|PATCH|DELETE)\s*\()/g;
const WRITE = /\bprisma\.(\w+)\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/g;
const PERMISSIONS = /requiredPermissions\s*:\s*\[([^\]]*)\]/g;
const ROLE_CHECK = /requiredRoles\s*:|\.role\s*(?:!==|===|!=|==)|role\s*(?:!==|===)\s*["'`]/;
const WRITE_ACTIONS = new Set(["write", "create", "update", "delete", "manage", "admin"]);

// Pages API: a named handler assignment or the default export itself owns a segment.
const PAGES_HANDLER_OWNER = /(?:^|\n)(?:export\s+default\s+(?:async\s+function\s+\w*\s*\(|[\w.]+\()|const\s+(\w+)\s*=\s*[\w.]+\()/g;
// `if (req.method === "GET") { return getHandler(req, res); }` binds an identifier to a method.
const PAGES_RETURN_DISPATCH = /req\.method\s*===\s*["'`](GET|POST|PUT|PATCH|DELETE)["'`][\s\S]{0,80}?\b(\w+)\s*\(\s*req/g;
const PAGES_INLINE_METHOD = /req\.method\s*===\s*["'`](GET|POST|PUT|PATCH|DELETE)["'`]/g;

/** `apiKeys`, `apikey`, `api_keys` and `ApiKey` all name the same resource. */
function resourceKey(name: string): string {
  const flat = name.replace(/[_-]/g, "").toLowerCase();
  return flat.endsWith("ies") ? `${flat.slice(0, -3)}y` : flat.endsWith("s") ? flat.slice(0, -1) : flat;
}

function readPermissions(segment: string): string[] | null {
  const lists = [...segment.matchAll(PERMISSIONS)];
  if (lists.length === 0 || ROLE_CHECK.test(segment)) return null;
  return [...new Set(lists.flatMap((list) => [...list[1].matchAll(/["'`]([\w.:-]+)["'`]/g)].map((p) => p[1])))].sort();
}

function handlers(file: string, content: string): Handler[] {
  const starts = [...content.matchAll(EXPORT)].map((m) => ({ index: m.index ?? 0, method: m[1] ?? m[2] }));
  return starts.map(({ index, method }, i) => {
    const segment = content.slice(index, i + 1 < starts.length ? starts[i + 1].index : content.length);
    const permissions = readPermissions(segment);
    if (!permissions) return [];
    return [{ file, method, permissions, writes: new Set([...segment.matchAll(WRITE)].map((w) => w[1])) }];
  }).flat();
}

function pagesApiHandlers(file: string, content: string): Handler[] {
  const owners = [...content.matchAll(PAGES_HANDLER_OWNER)].map((m) => ({ ident: m[1] ?? null, index: m.index ?? 0 }));
  if (owners.length === 0) return [];
  const dispatchMethod = new Map<string, string>();
  for (const m of content.matchAll(PAGES_RETURN_DISPATCH)) dispatchMethod.set(m[2], m[1]);

  return owners.map(({ ident, index }, i) => {
    const segment = content.slice(index, i + 1 < owners.length ? owners[i + 1].index : content.length);
    const permissions = readPermissions(segment);
    if (!permissions) return [];
    const inlineMethods = new Set([...segment.matchAll(PAGES_INLINE_METHOD)].map((m) => m[1]));
    // A single inline branch, or a dispatched identifier, names an unambiguous method.
    // More than one inline branch under one shared permission list can't be split into
    // per-method writes without risking a read branch's guard covering another's write.
    const method = inlineMethods.size === 1 ? [...inlineMethods][0] : inlineMethods.size === 0 && ident ? dispatchMethod.get(ident) : undefined;
    if (!method) return [];
    return [{ file, method, permissions, writes: new Set([...segment.matchAll(WRITE)].map((w) => w[1])) }];
  }).flat();
}

/** The permission this handler holds for a model's resource, if any. */
function guardFor(handler: Handler, model: string): string | null {
  const key = resourceKey(model);
  return handler.permissions.find((permission) => {
    const [resource, action] = permission.split(/[.:]/);
    return action !== undefined && WRITE_ACTIONS.has(action.toLowerCase()) && resourceKey(resource) === key;
  }) ?? null;
}

export function findPermissionGaps(files: { path: string; content: string }[]): PermissionGap[] {
  const all = files.flatMap((f) => {
    if (ROUTE_FILE.test(f.path)) return handlers(f.path, f.content);
    if (PAGES_API_FILE.test(f.path)) return pagesApiHandlers(f.path, f.content);
    return [];
  });
  const gaps: PermissionGap[] = [];
  for (const handler of all) {
    for (const model of [...handler.writes].sort()) {
      if (guardFor(handler, model)) continue;
      const witness = all
        .filter((other) => other !== handler && other.writes.has(model) && guardFor(other, model))
        .sort((a, b) => a.file.localeCompare(b.file) || a.method.localeCompare(b.method))[0];
      if (!witness) continue;
      gaps.push({ file: handler.file, method: handler.method, model, requires: handler.permissions,
        expected: guardFor(witness, model)!, witness: { file: witness.file, method: witness.method }, tier: "declared" });
    }
  }
  return gaps.sort((a, b) => a.file.localeCompare(b.file) || a.method.localeCompare(b.method) || a.model.localeCompare(b.model));
}
