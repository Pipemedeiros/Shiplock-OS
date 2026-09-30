import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// Q32 (Felipe 2026-09-29): every action says what happened. Each component
// already handles a failed response and a network error; this keeps the
// message announced to screen readers: errors as alerts, outcomes as status.
const files = execSync("git ls-files components", { encoding: "utf8" }).split("\n").filter((f) => /\.tsx$/.test(f) && !/\.test\./.test(f));

describe("outcome messages are announced", () => {
  it("renders every error with role alert and every outcome message with role status", () => {
    const missing: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      for (const match of source.matchAll(/\{(error|message) (?:\?|&&) (<[a-z]+[^>]*>)/g)) {
        const role = match[1] === "error" ? 'role="alert"' : 'role="status"';
        if (!match[2].includes(role)) missing.push(`${file}: ${match[2].slice(0, 50)}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
