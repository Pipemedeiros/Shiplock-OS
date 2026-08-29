import { describe, expect, it } from "vitest";
import { CONNECTION_CATEGORIES, categoryFor } from "./categories";
import type { StackKind } from "@/lib/agent/stack";

describe("CONNECTION_CATEGORIES", () => {
  it("gives every stack kind a home except framework", () => {
    // A detected tool with no category is a tool the stack screen silently
    // drops. Framework is deliberately excluded: there is nothing to connect to
    // Next.js, and offering it would be noise.
    const kinds: StackKind[] = [
      "auth", "database", "payments", "storage", "email", "hosting", "ai",
    ];
    for (const kind of kinds) {
      expect(categoryFor(kind), `${kind} has no category`).not.toBeNull();
    }
    expect(categoryFor("framework")).toBeNull();
  });

  it("claims no connector it does not have", () => {
    // The rule this file exists to hold: a connect target is a real route or
    // null. A button that opens nothing spends trust we do not get back.
    for (const category of CONNECTION_CATEGORIES) {
      if (category.connect !== null) {
        expect(category.connect, `${category.id} target must be a path`).toMatch(/^\//);
      }
    }
  });

  it("says what connecting reads, not how good it would be", () => {
    for (const category of CONNECTION_CATEGORIES) {
      expect(category.adds.length, `${category.id} needs a reason`).toBeGreaterThan(40);
      // The owner's copy rule: no dashes anywhere a customer reads.
      expect(category.adds, `${category.id} contains a dash`).not.toMatch(/[—–]| - /);
      expect(category.label).not.toMatch(/[—–]/);
    }
  });

  it("puts each kind in exactly one category", () => {
    const seen = new Set<string>();
    for (const category of CONNECTION_CATEGORIES) {
      for (const kind of category.kinds) {
        expect(seen.has(kind), `${kind} is in two categories`).toBe(false);
        seen.add(kind);
      }
    }
  });
});
