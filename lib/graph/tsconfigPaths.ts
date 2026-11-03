import ts from "typescript";
import type { RepoFile } from "@/lib/deep/githubScan";

/**
 * MONOREPO ALIAS RESOLUTION, the bounded half.
 *
 * `resolveImport` mapped `@/x` to `x`, `src/x` and `app/x`. That is the single-
 * app layout, and it is wrong for every workspace: corpus-a's routes live under
 * apps/web/ and import `@/lib/auth`, which is apps/web/lib/auth, so nothing
 * under `@/` resolved, 435 of 511 routes read as "wrapped in something we could
 * not read", and five corpus-c routes reached no table at all because the
 * real query sits behind an alias. Invisible rather than wrongly credited --
 * the right failure direction, and still silently unassessed.
 *
 * Surveyed across the five audited repositories on 2026-09-02, the alias forms
 * are: tsconfig `paths` (corpus-a 9301 specifiers, corpus-c 7538, corpus-b 4989,
 * corpus-d 1882, corpus-e 1190), workspace packages (`@corpus-a/utils`,
 * `@corpus-c/types`, `@corpus-e/db`), and nothing else -- no `#subpath`
 * imports in any of them.
 *
 * This module resolves the first form only. tsconfig `paths` is mechanical:
 * the nearest tsconfig.json above the importing file, its `baseUrl` (or its own
 * directory), and its pattern map. Workspace packages are NOT resolved here:
 * their package.json `main` mostly points at dist/ output that is not in the
 * archive, so mapping them is a heuristic, and on these corpora the packages
 * imported are UI, type and database-client libraries that carry no route
 * facts. `workspacePackageNames()` exists so a route that imports one can be
 * disclosed as unresolved rather than treated as a third-party dependency.
 *
 * The index is built once per file set and memoised on the Map itself.
 */

interface PathsConfig {
  /** Directory of the tsconfig, "" for the repository root. */
  dir: string;
  /** Directory `paths` targets are relative to. */
  base: string;
  paths: Record<string, string[]>;
}

interface AliasIndex {
  configs: PathsConfig[];
  packages: Set<string>;
}

const indexes = new WeakMap<Map<string, RepoFile>, AliasIndex>();

const EXTS = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const INDEXES = ["/index.ts", "/index.tsx", "/index.js", "/index.jsx"];

function join(...parts: string[]): string {
  const out: string[] = [];
  for (const part of parts.join("/").split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return out.join("/");
}

function buildIndex(byPath: Map<string, RepoFile>): AliasIndex {
  const configs: PathsConfig[] = [];
  const packages = new Set<string>();

  for (const [path, file] of byPath) {
    if (/(^|\/)(tsconfig|jsconfig)\.json$/.test(path)) {
      // TypeScript's own reader: tsconfig files carry comments and trailing
      // commas that JSON.parse refuses.
      const { config } = ts.parseConfigFileTextToJson(path, file.content);
      const paths = config?.compilerOptions?.paths;
      if (!paths || typeof paths !== "object") continue;
      const dir = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
      const baseUrl = typeof config.compilerOptions.baseUrl === "string" ? config.compilerOptions.baseUrl : ".";
      configs.push({ dir, base: join(dir, baseUrl), paths: paths as Record<string, string[]> });
    } else if (/(^|\/)package\.json$/.test(path)) {
      try {
        const name = JSON.parse(file.content)?.name;
        if (typeof name === "string" && name.length > 0) packages.add(name);
      } catch {
        // not JSON; not a package
      }
    }
  }

  // Deepest directory first, so the nearest config wins.
  configs.sort((a, b) => b.dir.length - a.dir.length);
  return { configs, packages };
}

function indexFor(byPath: Map<string, RepoFile>): AliasIndex {
  let index = indexes.get(byPath);
  if (!index) {
    index = buildIndex(byPath);
    indexes.set(byPath, index);
  }
  return index;
}

/**
 * The file `spec` names under the nearest tsconfig's `paths`, or null.
 *
 * Only a file that exists in the set is returned: a mapping that points at
 * nothing we ingested resolves to nothing, exactly as before.
 */
export function resolveViaTsconfigPaths(fromPath: string, spec: string, byPath: Map<string, RepoFile>): string | null {
  const { configs } = indexFor(byPath);
  const config = configs.find((c) => c.dir === "" || fromPath.startsWith(c.dir + "/"));
  if (!config) return null;

  for (const [pattern, targets] of Object.entries(config.paths)) {
    if (!Array.isArray(targets)) continue;
    const star = pattern.indexOf("*");
    const prefix = star === -1 ? pattern : pattern.slice(0, star);
    const suffix = star === -1 ? "" : pattern.slice(star + 1);
    const matches = star === -1 ? spec === pattern : spec.startsWith(prefix) && spec.endsWith(suffix) && spec.length >= prefix.length + suffix.length;
    if (!matches) continue;
    const captured = star === -1 ? "" : spec.slice(prefix.length, spec.length - suffix.length);

    for (const target of targets) {
      if (typeof target !== "string") continue;
      const mapped = join(config.base, target.replace("*", captured));
      for (const ext of EXTS) if (byPath.has(mapped + ext)) return mapped + ext;
      for (const idx of INDEXES) if (byPath.has(mapped + idx)) return mapped + idx;
    }
  }
  return null;
}

/** Names of packages declared inside this repository (workspace packages). */
function workspacePackageNames(byPath: Map<string, RepoFile>): Set<string> {
  return indexFor(byPath).packages;
}

/** True when `spec` imports a package that lives in this repository. */
export function isWorkspacePackageImport(spec: string, byPath: Map<string, RepoFile>): boolean {
  if (/^[.~#/]|^@\//.test(spec)) return false;
  const names = workspacePackageNames(byPath);
  const root = spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
  return names.has(root);
}
