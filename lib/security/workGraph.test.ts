import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The work graph (.agents/skills/work-graph) routes Claude's own work through
// the skills. A node naming a skill that does not exist, or a skill nothing
// routes to, is a fake edge; this keeps the graph and the skills in step.
const root = join(process.cwd(), ".agents/skills");
const graph = readFileSync(join(root, "work-graph/SKILL.md"), "utf8");
const skills = readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
const routed = new Set(graph.split("\n").filter((line) => /^\| [A-Z]/.test(line) && !line.startsWith("| Node "))
  .flatMap((line) => line.split("|").at(-2)!.split(",").map((s) => s.trim()).filter(Boolean)));

describe("work graph", () => {
  it("routes only to skills that exist", () => {
    for (const skill of routed) expect(existsSync(join(root, skill, "SKILL.md")), skill).toBe(true);
  });

  it("routes to every skill except itself", () => {
    expect([...routed].sort()).toEqual(skills.filter((s) => s !== "work-graph").sort());
  });

  it("gives every skill a name matching its folder and a trigger description", () => {
    for (const skill of skills) {
      const head = /^---\nname: (.+)\ndescription: (.+)\n---\n/.exec(readFileSync(join(root, skill, "SKILL.md"), "utf8"));
      expect(head?.[1], skill).toBe(skill);
      expect(head?.[2], skill).toMatch(/^(Use|How)\b/);
    }
  });

  it("keeps the skills short enough to read whole", () => {
    for (const skill of skills) {
      expect(readFileSync(join(root, skill, "SKILL.md"), "utf8").split("\n").length, skill).toBeLessThan(110);
    }
  });
});
