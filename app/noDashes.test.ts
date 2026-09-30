import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
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
