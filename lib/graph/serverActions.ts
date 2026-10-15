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
/** A module directive comes before any statement; comments may precede it
 * (R2: an inline "use server" inside a page's function marks that function,
 * not the file). */
function isServerModule(content: string): boolean {
  const head = content.replace(/^#![^\n]*\n/, "").replace(/^(\s+|\/\/[^\n]*\n?|\/\*[\s\S]*?\*\/)*/, "");
  return /^["']use server["']/.test(head);
}
const USE_CLIENT = /(^|\n)\s*["']use client["'];?\s*(\n|$)/;
const EXPORTED = /export\s+(?:async\s+)?(?:function\s+(\w+)|const\s+(\w+)\s*=)/g;
const NAMED_IMPORT = /import\s*(?:type\s+)?\{([^}]*)\}\s*from\s*["']([^"']+)["']/g;

// Client roots: a "use client" file, or a Pages Router page (rendered in the
// browser). A component file is client only when a root reaches it through
// imports (R2b, release attempt 3: corpus-z's sidebar, a server component
// outside app/, was counted as a browser entry). Unreached, it is a server
// component, and an App Router page or layout is the common case.
const PAGES_ROUTER_PAGE = /(^|\/)pages\/(?!api\/).+\.[jt]sx$/;
const ANY_IMPORT = /(?:import|export)\s[^'"]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

function clientReach(code: RepoFile[], byPath: Map<string, RepoFile>): Set<string> {
  const reached = new Set<string>();
  const queue = code.filter((f) => USE_CLIENT.test(f.content) || PAGES_ROUTER_PAGE.test(f.path)).map((f) => f.path);
  while (queue.length) {
    const path = queue.pop()!;
    if (reached.has(path)) continue;
    reached.add(path);
    const file = byPath.get(path);
    if (!file || isServerModule(file.content)) continue;
    for (const [, spec, dynamic] of file.content.matchAll(ANY_IMPORT)) {
      const target = resolveImport(path, spec ?? dynamic, byPath) ?? resolveViaTsconfigPaths(path, spec ?? dynamic, byPath);
      if (target && !reached.has(target)) queue.push(target);
    }
  }
  return reached;
}

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
    if (!isServerModule(file.content)) continue;
    actions.set(file.path, new Set([...file.content.matchAll(EXPORTED)].map((m) => m[1] ?? m[2])));
  }
  const client = clientReach(code, byPath);
  const importers = new Map<string, Set<string>>(); // "file#name" -> importing UI files
  for (const file of code) {
    if (isServerModule(file.content) || !isUi(file)) continue;
    for (const [, names, spec] of file.content.matchAll(NAMED_IMPORT)) {
      const target = resolveImport(file.path, spec, byPath) ?? resolveViaTsconfigPaths(file.path, spec, byPath);
      const exported = target ? actions.get(target) : undefined;
      if (!target || !exported) continue;
      for (const raw of names.split(",")) {
        const [name, alias] = raw.trim().replace(/^type\s+/, "").split(/\s+as\s+/).map((x) => x.trim());
        if (!name || !exported.has(name)) continue;
        // A server component (no client root reaches it) exposes the action
        // only by handing it to the browser: a form or button action, or a
        // prop to a client component. Awaiting it on the server sends no id
        // (A8 batch 6, 2026-10-09; R2b, 2026-10-13).
        if (!client.has(file.path) && !handsOver(file.content, alias ?? name)) continue;
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
