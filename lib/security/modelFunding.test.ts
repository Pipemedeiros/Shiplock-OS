import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// ShipLock pays for no intelligence (Felipe, 2026-10-01, AGENTS.md Product).
// The customer's own agent, over MCP, is the only AI path. So no product file
// may construct a model client, import a model SDK, call a model API host, or
// read a model key or a funded-call switch. The offline corpus harness under
// scripts/ is a developer tool Felipe runs on his own key and is out of scope.
const PRODUCT = ["app", "lib", "components", "mcp/index.mjs", "proxy.ts"];
const MODEL_SDK = /from\s+["'](?:@anthropic-ai\/|openai["'/]|@ai-sdk\/|ai["']|@google\/(?:generative-ai|genai)|@mistralai\/|cohere-ai|groq-sdk)|require\(\s*["'](?:@anthropic-ai\/|openai)|import\(\s*["'](?:@anthropic-ai\/|openai)/;
const MODEL_HOST = /api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com/;
const MODEL_KEY = /process\.env(?:\.|\[\s*["'])(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|SHIPLOCK_FUNDED_[A-Z_]+)/;

function sources(path: string): string[] {
  if (!statSync(path).isDirectory()) return [path];
  return readdirSync(path).flatMap((name) => {
    const child = join(path, name);
    if (statSync(child).isDirectory()) return name === "node_modules" ? [] : sources(child);
    return /\.(ts|tsx|mjs|js)$/.test(name) && !/\.test\./.test(name) ? [child] : [];
  });
}
const product = PRODUCT.flatMap(sources).map((file) => ({ file, code: readFileSync(file, "utf8") }));

describe("ShipLock makes no model call of its own", () => {
  it("reads every product source", () => {
    expect(product.length).toBeGreaterThan(200);
  });

  it("no product file imports a model SDK or constructs a model client", () => {
    expect(product.filter(({ code }) => MODEL_SDK.test(code) || /new Anthropic\(|new OpenAI\(/.test(code)).map((s) => s.file)).toEqual([]);
  });

  it("no product file names a model API host", () => {
    expect(product.filter(({ code }) => MODEL_HOST.test(code)).map((s) => s.file)).toEqual([]);
  });

  it("no product file reads a model key or a funded-call switch", () => {
    expect(product.filter(({ code }) => MODEL_KEY.test(code)).map((s) => s.file)).toEqual([]);
  });

  it("the app starts without a model key", () => {
    expect(readFileSync("lib/env.ts", "utf8")).not.toMatch(/ANTHROPIC_API_KEY/);
  });

  it("the model SDK is not a runtime dependency of the app", () => {
    const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { dependencies?: Record<string, string> };
    expect(Object.keys(pkg.dependencies ?? {}).filter((d) => /^@anthropic-ai\/|^openai$/.test(d))).toEqual([]);
  });
});
