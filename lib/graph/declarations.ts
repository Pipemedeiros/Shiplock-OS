import ts from "typescript";

/**
 * THE DECLARATION RULE: evidence is drawn from behaviour, never from shape.
 *
 * Every collector in routeInventory.ts matches tokens in source text, and a
 * token in a declaration is not the thing the collector is looking for. An
 * interface field named `userId` is not a query narrowed to the caller; an
 * import of `getServerSession` is not a session check; `typeof
 * prisma.user.findMany` inside a type is not a read of `user`. Measured on
 * corpus-b before the ownership pattern was tightened, 20 of 25 spurious
 * ownership matches came from exactly these shapes -- most of them four
 * `userId: string;` lines in lib/types.ts, which every route reaches.
 *
 * This blanks the spans that describe shape so the patterns cannot see them,
 * and it does so with the TypeScript parser rather than more regex, because
 * "where does a type annotation end" is not a question a regex answers. The
 * output is the same length as the input, newline for newline, so any offset
 * or line number computed on it is an offset into the original.
 *
 * Blanked:
 *   - import declarations           an imported name is not a call
 *   - interface / type / enum / namespace / `declare` statements
 *   - every type annotation, assertion, and type argument
 *   - parameter names and destructuring patterns   a binding is not a use
 *   - `select:` / `include:` / `omit:` projection literals   a projection is
 *     a column list, not a filter
 *
 * NOT blanked, deliberately: Zod schemas. They are ordinary expressions, and
 * under the tightened ownership pattern a schema body cannot match a filter
 * position by construction (`routeInventory.stacks.test.ts` pins that). Naming
 * a library here would be a wordlist, and the parser has no opinion about it.
 *
 * Parse failures never fail the collector: a file the parser cannot read is
 * returned unchanged, which is the behaviour before this rule existed.
 */

const PROJECTION_KEYS = new Set(["select", "include", "omit"]);

/** A small memo: the same helper is reached from many routes in one run. */
const cache = new Map<string, string>();
const CACHE_LIMIT = 4_000;

/** The TypeScript parser mode for a file's extension. */
export function scriptKindFor(path: string): ts.ScriptKind {
  if (/\.tsx$/.test(path)) return ts.ScriptKind.TSX;
  if (/\.jsx$/.test(path)) return ts.ScriptKind.JSX;
  if (/\.(js|mjs|cjs)$/.test(path)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function isDeclarationStatement(node: ts.Node): boolean {
  if (
    ts.isImportDeclaration(node) ||
    ts.isImportEqualsDeclaration(node) ||
    ts.isInterfaceDeclaration(node) ||
    ts.isTypeAliasDeclaration(node) ||
    ts.isEnumDeclaration(node) ||
    ts.isModuleDeclaration(node)
  ) {
    return true;
  }
  const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return mods?.some((m) => m.kind === ts.SyntaxKind.DeclareKeyword) ?? false;
}

function isProjection(node: ts.Node): node is ts.PropertyAssignment {
  return (
    ts.isPropertyAssignment(node) &&
    ts.isObjectLiteralExpression(node.initializer) &&
    (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) &&
    PROJECTION_KEYS.has(node.name.text)
  );
}

/** Source with declarations blanked to spaces. Same length, same line breaks. */
export function blankDeclarations(src: string, path = "file.ts"): string {
  const key = `${scriptKindFor(path)} ${src}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;

  let out: string;
  try {
    out = blank(src, path);
  } catch {
    out = src;
  }

  if (cache.size >= CACHE_LIMIT) cache.clear();
  cache.set(key, out);
  return out;
}

/** Blank `[start, end)` spans to spaces, keeping every line break in place. */
export function blankSpans(src: string, spans: [number, number][]): string {
  if (spans.length === 0) return src;
  const chars = src.split("");
  for (const [start, end] of spans) {
    for (let i = start; i < end && i < chars.length; i++) {
      const c = chars[i];
      if (c !== "\n" && c !== "\r") chars[i] = " ";
    }
  }
  return chars.join("");
}

/** The declaration spans of a parsed file. Exported so the call-path walk can reuse the parse. */
export function declarationSpans(sf: ts.SourceFile): [number, number][] {
  const spans: [number, number][] = [];
  const add = (node: ts.Node) => spans.push([node.getStart(sf), node.end]);

  const visit = (node: ts.Node): void => {
    if (isDeclarationStatement(node)) {
      add(node);
      return; // nothing inside a declaration is behaviour
    }
    if (ts.isTypeNode(node)) {
      add(node);
      return;
    }
    // A PARENTHESISED TYPE ASSERTION takes its parentheses with it.
    // `(session.user as CustomUser).id` is the corpus-b idiom -- 185 files,
    // 199 routes -- and blanking only the type left `(session.user       ).id`,
    // where the parentheses exist SOLELY to scope a type that no longer
    // exists. Every caller-identity pattern was blind to it, and 13
    // table-touching routes read as unscoped for that reason alone. Erasing
    // the punctuation with the type is the declaration rule doing its job:
    // shape is removed, and the expression underneath is left where it was.
    // Fixed here rather than in the patterns because one fix serves all seven
    // of them; loosening a pattern to tolerate `as` and a paren would fix that
    // pattern and leave the same blindness in the other six.
    if (ts.isParenthesizedExpression(node)) {
      const inner = node.expression;
      if (ts.isAsExpression(inner) || ts.isSatisfiesExpression(inner)) {
        const start = node.getStart(sf);
        spans.push([start, start + 1]);
        spans.push([node.end - 1, node.end]);
        spans.push([inner.expression.end, inner.end]);
        visit(inner.expression);
        return;
      }
    }
    if (ts.isParameter(node)) {
      add(node.name);
      if (node.type) add(node.type);
      if (node.initializer) visit(node.initializer);
      return;
    }
    if (ts.isVariableDeclaration(node) && (ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name))) {
      add(node.name);
    }
    if (isProjection(node)) {
      blankProjection(node.initializer as ts.ObjectLiteralExpression);
      return;
    }
    ts.forEachChild(node, visit);
  };

  // A projection is a column list, and a column list is shape -- EXCEPT that
  // Prisma lets a relation inside `select`/`include` carry its own `where`,
  // and that `where` is behaviour. corpus-a's /api/domains/[domain]/transfer checks
  // membership with `select: { users: { where: { userId: session.user.id } } }`
  // and the first version of this rule blanked the check along with the
  // columns around it. Only the leaves are blanked; a nested `where` is
  // visited like any other code.
  const blankProjection = (literal: ts.ObjectLiteralExpression): void => {
    for (const prop of literal.properties) {
      if (ts.isPropertyAssignment(prop)) {
        const name = ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name) ? prop.name.text : null;
        if (name === "where") {
          visit(prop.initializer);
        } else if (ts.isObjectLiteralExpression(prop.initializer)) {
          blankProjection(prop.initializer);
        } else {
          add(prop);
        }
      } else {
        add(prop); // shorthand, spread, method: none of it is a filter
      }
    }
  };
  visit(sf);
  return spans;
}

function blank(src: string, path: string): string {
  const sf = ts.createSourceFile(path, src, ts.ScriptTarget.Latest, true, scriptKindFor(path));
  return blankSpans(src, declarationSpans(sf));
}
