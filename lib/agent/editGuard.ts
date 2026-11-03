import ts from "typescript";

/**
 * The gate every machine-authored code change passes before it reaches a
 * customer's repository.
 *
 * The promise attached to a fix pull request is that reviewing it is cheap and
 * merging it is safe. A patch that does not parse breaks that on contact — the
 * author opens it, sees a syntax error, and never trusts a ShipLock pull
 * request again. So a change is only offered when all of the following hold,
 * checked here rather than assumed:
 *
 *   1. The result parses as the language it claims to be.
 *   2. It introduces no new syntax diagnostics the original did not have.
 *   3. It is a real change, and a BOUNDED one — we do not rewrite a file.
 *   4. Every identifier the change references already existed in the file, so
 *      the edit cannot depend on an import nobody added.
 *
 * None of this proves the customer's tests still pass. It cannot: we do not
 * have their test suite, their environment or their intent. What it does prove
 * is that the file is still a file, and that is the floor beneath which we must
 * never ship. Everything above that floor is why a human approves the merge.
 */

type RejectionReason =
  | "unchanged"
  | "unsupported_language"
  | "does_not_parse"
  | "new_syntax_errors"
  | "too_large"
  | "unknown_identifier";

type EditVerdict =
  | { safe: true; added: number; removed: number }
  | { safe: false; reason: RejectionReason; detail: string };

/**
 * Names that are always in scope and need no import.
 *
 * Without this the guard rejects a change for referencing `undefined`, which is
 * both correct as a rule and useless as a product.
 */
const AMBIENT = new Set([
  "undefined", "null", "true", "false", "globalThis", "console", "process", "JSON", "Math",
  "Object", "Array", "String", "Number", "Boolean", "Symbol", "BigInt", "Promise", "Date",
  "Error", "TypeError", "RangeError", "Map", "Set", "WeakMap", "WeakSet", "RegExp", "Proxy",
  "Reflect", "Infinity", "NaN", "parseInt", "parseFloat", "isNaN", "encodeURIComponent",
  "decodeURIComponent", "setTimeout", "clearTimeout", "setInterval", "clearInterval",
  "fetch", "Request", "Response", "Headers", "URL", "URLSearchParams", "AbortController",
  "AbortSignal", "Buffer", "TextEncoder", "TextDecoder", "crypto", "structuredClone",
  "String", "Function", "Intl", "atob", "btoa",
]);

/** Above this share of the file, it is a rewrite and a human should write it. */
const MAX_CHANGED_RATIO = 0.4;
const MAX_CHANGED_LINES = 60;

const PARSEABLE = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

/**
 * Whether this guard can judge the file at all.
 *
 * Everything below reads the file with a TypeScript parser. Handed a .py or a
 * .sql it would still return a verdict, and that verdict would be noise wearing
 * the costume of a check. A language we cannot parse is refused, not guessed
 * at: the guard's whole value is that a `safe: true` means something.
 */
export function isParseable(path: string): boolean {
  return PARSEABLE.some((ext) => path.endsWith(ext));
}

function scriptKind(path: string): ts.ScriptKind {
  if (path.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (path.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (path.endsWith(".js") || path.endsWith(".mjs") || path.endsWith(".cjs")) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/**
 * Syntax diagnostics only — we have no type information for someone else's repo.
 *
 * Returns null when the parser did not give us diagnostics at all, which is a
 * different answer from zero and must never be flattened into it.
 * `parseDiagnostics` is internal to TypeScript; if a version renames it, a
 * `?? []` here would report every broken file as clean and the guard would wave
 * through the one change it exists to stop. Unknown fails closed.
 */
export function syntaxErrorCount(path: string, source: string): number | null {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, scriptKind(path));
  const diagnostics = (file as unknown as { parseDiagnostics?: unknown[] }).parseDiagnostics;
  if (!Array.isArray(diagnostics)) return null;
  return diagnostics.length;
}

function lineDiff(before: string, after: string): { added: number; removed: number } {
  const a = new Set(before.split("\n").map((l) => l.trim()).filter(Boolean));
  const b = after.split("\n").map((l) => l.trim()).filter(Boolean);
  const added = b.filter((l) => !a.has(l)).length;
  const bSet = new Set(b);
  const removed = [...a].filter((l) => !bSet.has(l)).length;
  return { added, removed };
}

/** Identifiers the file already knows about, so an edit cannot invent a symbol. */
export function identifiersIn(path: string, source: string): Set<string> {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, scriptKind(path));
  const names = new Set<string>();

  const walk = (node: ts.Node) => {
    // Property NAMES are not free identifiers. `JSON.stringify` reads as the
    // identifiers JSON and stringify in the AST, and treating the second as a
    // symbol needing an import rejected every correct edit that called a
    // method. Only the object side of a dot, and only real references, count.
    if (ts.isPropertyAccessExpression(node)) {
      walk(node.expression);
      return;
    }
    if (ts.isPropertyAssignment(node) || ts.isPropertySignature(node) || ts.isMethodDeclaration(node)) {
      // The key is a name, not a reference. The value still is.
      node.forEachChild((child) => {
        if (child !== node.name) walk(child);
      });
      return;
    }
    if (ts.isIdentifier(node)) names.add(node.text);
    node.forEachChild(walk);
  };

  walk(file);
  return names;
}

/**
 * Names the file DECLARES: imports, variables, parameters, functions, classes.
 *
 * The unknown-identifier rule needs this to tell two different edits apart. An
 * edit that calls `and(...)` without importing it will not compile in the
 * customer's repository. An edit that writes `const and = ...` and then calls
 * it is fine. Both introduce the identifier `and`; only the first is a bug.
 */
function declaredIn(path: string, source: string): Set<string> {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, scriptKind(path));
  const names = new Set<string>();

  const bindName = (name: ts.BindingName | undefined) => {
    if (!name) return;
    if (ts.isIdentifier(name)) names.add(name.text);
    else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
      for (const element of name.elements) {
        if (ts.isBindingElement(element)) bindName(element.name);
      }
    }
  };

  const walk = (node: ts.Node) => {
    if (ts.isVariableDeclaration(node) || ts.isParameter(node)) bindName(node.name);
    else if (
      (ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node) || ts.isEnumDeclaration(node)) &&
      node.name
    ) names.add(node.name.text);
    else if (ts.isImportClause(node) && node.name) names.add(node.name.text);
    else if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node)) names.add(node.name.text);
    node.forEachChild(walk);
  };
  walk(file);
  return names;
}

/** Whether a proposed edit is safe to offer: it must change something, parse,
 * and stay within what a mechanical fix may touch. */
export function judgeEdit(path: string, before: string, after: string): EditVerdict {
  if (before === after) {
    return { safe: false, reason: "unchanged", detail: "The change is a no-op." };
  }

  if (!isParseable(path)) {
    return {
      safe: false,
      reason: "unsupported_language",
      detail: `We cannot parse ${path}, so we cannot promise this change is even syntactically whole.`,
    };
  }

  const beforeErrors = syntaxErrorCount(path, before);
  const afterErrors = syntaxErrorCount(path, after);

  if (beforeErrors === null || afterErrors === null) {
    return {
      safe: false,
      reason: "does_not_parse",
      detail: "The parser reported no diagnostics of any kind, so we cannot tell a whole file from a broken one.",
    };
  }

  if (afterErrors > 0 && beforeErrors === 0) {
    return {
      safe: false,
      reason: "does_not_parse",
      detail: `The edited file has ${afterErrors} syntax error${afterErrors === 1 ? "" : "s"}; the original had none.`,
    };
  }
  if (afterErrors > beforeErrors) {
    return {
      safe: false,
      reason: "new_syntax_errors",
      detail: `Syntax errors went from ${beforeErrors} to ${afterErrors}.`,
    };
  }

  const { added, removed } = lineDiff(before, after);

  // Whitespace or reordering only. Not a rejection worth explaining — there is
  // simply nothing to open a pull request about.
  if (added === 0 && removed === 0) {
    return { safe: false, reason: "unchanged", detail: "Only whitespace changed." };
  }

  const total = before.split("\n").filter((l) => l.trim()).length || 1;

  // Deleting most of a file is a rewrite. This needs a small absolute floor as
  // well as the fraction: on a one-line file, editing that line reads as 100%
  // removed, and a genuine two-line fix should not be rejected as a rewrite.
  // Six lines is the point where "replaced the file" stops being "edited it".
  if (removed >= 6 && removed / total > 0.6) {
    return {
      safe: false,
      reason: "too_large",
      detail: `The change removes ${removed} of ${total} lines. Replacing a file is a rewrite, and a human should write it.`,
    };
  }

  // The ratio is meaningless on a short file: changing one line of a five-line
  // module is 20%, and changing one line of a one-line module is everything.
  // Below the floor only the absolute cap applies.
  const RATIO_FLOOR = 20;
  const tooBigByRatio = total >= RATIO_FLOOR && (added + removed) / total > MAX_CHANGED_RATIO;
  if (added + removed > MAX_CHANGED_LINES || tooBigByRatio) {
    return {
      safe: false,
      reason: "too_large",
      detail: `${added + removed} lines changed in a ${total}-line file. A change this size is a rewrite, and a human should write it.`,
    };
  }

  // Every identifier in the result must already have existed, OR be declared by
  // the change itself. An edit that merely CALLS a new symbol needs an import
  // nobody added, and the file will not compile in the customer's repository
  // even though it parses here.
  const known = identifiersIn(path, before);
  const declared = declaredIn(path, after);
  for (const name of identifiersIn(path, after)) {
    if (!known.has(name) && !declared.has(name) && !AMBIENT.has(name)) {
      return {
        safe: false,
        reason: "unknown_identifier",
        detail: `The change references "${name}", which does not appear in the file. It would need an import we cannot add safely.`,
      };
    }
  }

  return { safe: true, added, removed };
}
