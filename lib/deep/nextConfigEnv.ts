import ts from "typescript";
import { jwtRole } from "./clientExposure";
import { hasParseablePrivateKey, type GithubFinding, type RepoFile } from "./githubScan";

const CONFIG_PATH = /(^|\/)next\.config\.(?:js|mjs|ts)$/i;
const PUBLIC_ENV = /^NEXT_PUBLIC_/;
const CREDENTIAL_VALUES: { id: string; label: string; re: RegExp }[] = [
  { id: "private_key", label: "a PEM private key", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/ },
  { id: "supabase_service_key", label: "a Supabase service-role key", re: /\bsb_secret_[A-Za-z0-9_-]{10,}/ },
  { id: "aws_access_key", label: "an AWS access key id", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: "stripe_key", label: "a Stripe secret key", re: /\bsk_(?:live|test)_[A-Za-z0-9]{10,}/ },
  { id: "anthropic_key", label: "an Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{10,}/ },
  { id: "github_key", label: "a GitHub personal access token", re: /\bghp_[A-Za-z0-9]{20,}/ },
  { id: "openai_key", label: "an OpenAI API key", re: /\bsk-[A-Za-z0-9]{20,}\b/ },
];

function unwrap(node: ts.Expression): ts.Expression {
  while (
    ts.isParenthesizedExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node) ||
    ts.isTypeAssertionExpression(node)
  ) {
    node = node.expression;
  }
  return node;
}

function propertyName(node: ts.PropertyName): string | null {
  if (ts.isComputedPropertyName(node)) {
    const value = unwrap(node.expression);
    return ts.isStringLiteralLike(value) ? value.text : null;
  }
  return ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node) ? node.text : null;
}

function member(node: ts.Expression): { owner: ts.Expression; name: string } | null {
  node = unwrap(node);
  if (ts.isPropertyAccessExpression(node)) return { owner: unwrap(node.expression), name: node.name.text };
  if (ts.isElementAccessExpression(node) && ts.isStringLiteralLike(unwrap(node.argumentExpression))) {
    return { owner: unwrap(node.expression), name: (unwrap(node.argumentExpression) as ts.StringLiteralLike).text };
  }
  return null;
}

function processEnvName(node: ts.Expression): string | null {
  const value = member(node);
  const env = value && member(value.owner);
  return env && env.name === "env" && ts.isIdentifier(env.owner) && env.owner.text === "process" ? value!.name : null;
}

/** Only local immutable literal configuration is understood. Function exports,
 * wrappers, mutations and other executable module statements stay unresolved;
 * this collector makes no claim about their eventual configuration. */
function exportedEnv(source: ts.SourceFile): Map<string, ts.Expression> | null {
  const declarations = new Map<string, ts.Expression>();
  let value: ts.Expression | null = null;
  let dynamic = false;
  for (const statement of source.statements) {
    if (ts.isVariableStatement(statement)) {
      if (!(statement.declarationList.flags & ts.NodeFlags.Const)) return null;
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) return null;
        declarations.set(declaration.name.text, declaration.initializer);
      }
    } else if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
      value = statement.expression;
    } else if (ts.isExportDeclaration(statement) && !statement.moduleSpecifier && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
      const entry = statement.exportClause.elements.find((item) => item.name.text === "default");
      if (entry) value = entry.propertyName ?? entry.name;
    } else if (ts.isExpressionStatement(statement)) {
      const expr = statement.expression;
      const target = ts.isBinaryExpression(expr) ? member(expr.left) : null;
      if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.EqualsToken && target?.name === "exports" && ts.isIdentifier(target.owner) && target.owner.text === "module") {
        value = expr.right;
      } else if (!ts.isStringLiteral(expr)) return null;
    } else if (!ts.isImportDeclaration(statement) && !ts.isInterfaceDeclaration(statement) && !ts.isTypeAliasDeclaration(statement) && !ts.isEmptyStatement(statement)) {
      return null;
    }
  }
  // Calls in initializers can mutate an aliased config before export. Without
  // executing or tracing customer code, that final structure is unknown.
  const checkDynamic = (node: ts.Node) => {
    if (ts.isFunctionLike(node)) return;
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) dynamic = true;
    ts.forEachChild(node, checkDynamic);
  };
  for (const initializer of declarations.values()) checkDynamic(initializer);
  if (dynamic || !value || declarations.has("process") || declarations.has("module")) return null;

  function resolve(expr: ts.Expression, seen = new Set<string>()): ts.Expression | null {
    expr = unwrap(expr);
    if (!ts.isIdentifier(expr)) return expr;
    if (seen.has(expr.text)) return null;
    seen.add(expr.text);
    const declaration = declarations.get(expr.text);
    return declaration ? resolve(declaration, seen) : null;
  }
  function properties(expr: ts.Expression, seen = new Set<ts.Node>()): Map<string, ts.Expression> | null {
    const object = resolve(expr);
    if (!object || !ts.isObjectLiteralExpression(object) || seen.has(object)) return null;
    const ancestry = new Set(seen).add(object);
    const result = new Map<string, ts.Expression>();
    for (const property of object.properties) {
      if (ts.isSpreadAssignment(property)) {
        const spread = properties(property.expression, ancestry);
        if (!spread) result.clear();
        else for (const [name, initializer] of spread) result.set(name, initializer);
        continue;
      }
      const name = property.name && propertyName(property.name);
      if (!name) { result.clear(); continue; }
      if (ts.isPropertyAssignment(property)) result.set(name, property.initializer);
      else if (ts.isShorthandPropertyAssignment(property)) result.set(name, property.name);
      else result.delete(name);
    }
    return result;
  }
  const config = properties(value);
  const env = config?.get("env");
  return env ? properties(env) : null;
}

/**
 * Reads Next.js's explicit `env` map. Every entry in that map is replaced at
 * build time and can appear in browser JavaScript regardless of its prefix.
 */
export function scanNextConfigEnv(files: RepoFile[]): GithubFinding[] {
  const findings: GithubFinding[] = [];
  for (const file of files) {
    if (!CONFIG_PATH.test(file.path)) continue;
    const source = ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true);
    const env = exportedEnv(source);
    if (!env) continue;

    for (const [target, initializer] of env) {
      const value = unwrap(initializer);
      const sourceName = processEnvName(value);
      if (sourceName && !PUBLIC_ENV.test(sourceName)) {
        findings.push({
          id: `github:next_config_env:${target}:${file.path}`,
          severity: "WARNING",
          title: `${file.path} makes ${sourceName} available for client builds`,
          consequence: `${file.path} maps process.env.${sourceName} into the Next.js env block as ${target}. Next.js replaces env-block entries at build time, so the configured value can appear in the JavaScript bundle served to every visitor. Review whether this value is intended to be public. If it is private, remove it from the env block and read it only in server code.`,
          packageName: null, version: null, vulnId: null, cveId: null,
        });
        continue;
      }
      if (!ts.isStringLiteralLike(value)) continue;
      const credential = jwtRole(value.text) === "service_role" ? { label: "a Supabase service-role JWT" } : CREDENTIAL_VALUES.find((candidate) =>
        candidate.re.test(value.text) && (candidate.id !== "private_key" || hasParseablePrivateKey(value.text))
      );
      if (!credential) continue;
      findings.push({
        id: `github:next_config_env_credential:${target}:${file.path}`,
        severity: "CRITICAL",
        title: `${file.path} makes ${credential.label} available for client builds`,
        consequence: `${file.path} places ${credential.label} directly in the Next.js env block as ${target}. Next.js replaces env-block entries at build time, so the credential can appear in browser JavaScript when the entry is used in client code. Rotate it and remove it from the env block.`,
        packageName: null, version: null, vulnId: null, cveId: null,
      });
    }
  }
  return findings;
}
