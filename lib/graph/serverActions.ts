import type { RepoFile } from "@/lib/deep/githubScan";
import { resolveImport } from "@/lib/deep/clientExposure";
import { resolveViaTsconfigPaths } from "./tsconfigPaths";

/**
 * Server actions the browser can call (Step 7E-1). A `"use server"` file's
 * exports are callable from the client only when UI code imports them: a
 * `"use client"` file or a React component file (.tsx/.jsx), which may bind
 * the action to a form. A `"use server"` helper imported only by other server
 * code or a route handler is not an entry point, and treating it as one reads
 * helpers whose callers authorize as "anyone can call this".
 */
export type ServerActionEntry = { file: string; name: string; importedBy: string[] };

const IGNORED = /(^|\/)(node_modules|\.next|dist|build|vendor)\/|\.(test|spec)\.[cm]?[jt]sx?$/;
const CODE = /\.[cm]?[jt]sx?$/;
const USE_SERVER = /(^|\n)\s*["']use server["'];?\s*(\n|$)/;
const USE_CLIENT = /(^|\n)\s*["']use client["'];?\s*(\n|$)/;
const EXPORTED = /export\s+(?:async\s+)?(?:function\s+(\w+)|const\s+(\w+)\s*=)/g;
const NAMED_IMPORT = /import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*["']([^"']+)["']/g;

// App Router segment files no client imports: without "use client" they are
// server components. Any other .tsx may inherit a client boundary.
const SERVER_COMPONENT_FILE = /(^|\/)app\/(.+\/)?(page|layout|template|default)\.[jt]sx$/;

function handsOver(content: string, local: string): boolean {
  // Conservative: the page keeps the action on the server only when every use
  // of it, outside its import, is a direct call. Any other reference (a form
  // action, a prop, an object or array handed to a client component, corpus-am's
  // api={{ resume: resumePlan }}) may send its id to the browser.
  const esc = local.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const body = content.replace(/import\s[^;]*?from\s*["'][^"']+["'];?/g, "");
  return [...body.matchAll(new RegExp(`\\b${esc}\\b(?!\\s*\\()`, "g"))].length > 0;
}

function isUi(file: RepoFile): boolean {
  return USE_CLIENT.test(file.content) || /\.[jt]sx$/.test(file.path);
}

export function findServerActionEntries(files: RepoFile[]): ServerActionEntry[] {
  const code = files.filter((f) => CODE.test(f.path) && !IGNORED.test(f.path));
  const byPath = new Map(files.map((f) => [f.path, f]));
  const actions = new Map<string, Set<string>>();
  for (const file of code) {
    if (!USE_SERVER.test(file.content)) continue;
    actions.set(file.path, new Set([...file.content.matchAll(EXPORTED)].map((m) => m[1] ?? m[2])));
  }
  const importers = new Map<string, Set<string>>(); // "file#name" -> importing UI files
  for (const file of code) {
    if (USE_SERVER.test(file.content) || !isUi(file)) continue;
    for (const [, names, spec] of file.content.matchAll(NAMED_IMPORT)) {
      const target = resolveImport(file.path, spec, byPath) ?? resolveViaTsconfigPaths(file.path, spec, byPath);
      const exported = target ? actions.get(target) : undefined;
      if (!target || !exported) continue;
      for (const raw of names.split(",")) {
        const [name, alias] = raw.trim().replace(/^type\s+/, "").split(/\s+as\s+/).map((x) => x.trim());
        if (!name || !exported.has(name)) continue;
        // A server component (an App Router page or layout without "use client") exposes the action
        // only by handing it to the browser: a form or button action, or a
        // prop to a client component. Awaiting it on the server sends no id
        // (A8 batch 6, 2026-10-09).
        if (SERVER_COMPONENT_FILE.test(file.path) && !USE_CLIENT.test(file.content) && !handsOver(file.content, alias ?? name)) continue;
        const key = `${target}#${name}`;
        importers.set(key, new Set([...(importers.get(key) ?? []), file.path]));
      }
    }
  }
  return [...importers.entries()].map(([key, by]) => {
    const [file, name] = key.split("#");
    return { file, name, importedBy: [...by].sort() };
  }).sort((a, b) => a.file.localeCompare(b.file) || a.name.localeCompare(b.name));
}
