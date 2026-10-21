import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// These panels render inside the v3 Settings page, where Design D's variables
// (defined on .dxd) do not exist: a .dxd-btn there had no background, so its
// actions read as plain text (seen 2026-10-20). They use v3 classes and tokens.
const PANELS = [
  "components/d/SupabasePanel.tsx", "components/d/PostgresPanel.tsx", "components/d/VerifiedPanel.tsx",
  "components/d/DirectRepositoryAssociation.tsx", "components/sign-out-button.tsx",
];

describe("Settings panels inside the v3 shell", () => {
  for (const file of PANELS) {
    it(`${file} uses no Design D class or variable`, () => {
      const src = readFileSync(file, "utf8");
      expect(src).not.toMatch(/dxd-|var\(--d-/);
    });
  }
});
