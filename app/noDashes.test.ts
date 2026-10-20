import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import ts from "typescript";
import { expect, it } from "vitest";

// Felipe (2026-08-29, restated 2026-09-29): no dashes anywhere a customer
// reads. Every live page and component, comments excluded.
it("no em or en dash in any page or component outside comments", () => {
  const files = execSync("git ls-files app components", { encoding: "utf8" }).split("\n")
    .filter((f) => /\.tsx$/.test(f) && !/\.test\./.test(f));
  const hits: string[] = [];
  for (const file of files) {
    const code = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\{\/\*[\s\S]*?\*\/\}/g, "")
      .split("\n").map((line) => line.replace(/(^|[^:"'`])\/\/.*$/, "$1"));
    code.forEach((line, i) => { if (/[—–]/.test(line)) hits.push(`${file}:${i + 1}`); });
  }
  expect(hits).toEqual([]);
});

// Finding titles, consequences, emails and PR text are written in lib, and a
// founder reads every one (2026-10-19: 145 strings carried a dash). Strings
// only, read from the syntax tree, so comments and code stay free.
it("no dash in any string literal under lib", () => {
  const files = execSync("git ls-files lib", { encoding: "utf8" }).split("\n")
    .filter((f) => /\.ts$/.test(f) && !/\.test\./.test(f));
  const hits: string[] = [];
  for (const file of files) {
    const source = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
    const visit = (node: ts.Node) => {
      if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateHead(node)
          || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) && /[—–]| -- /.test(node.text)) {
        hits.push(`${file}:${source.getLineAndCharacterOfPosition(node.getStart()).line + 1}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  expect(hits).toEqual([]);
});
