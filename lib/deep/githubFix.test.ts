import { describe, expect, it } from "vitest";
import {
  compareSemver,
  fixedVersionFromOsv,
  pickTargetVersion,
  planDependencyBumps,
  buildPrBody,
} from "./githubFix";
import type { OsvVuln } from "./githubScan";

const vuln = (over: Partial<OsvVuln> = {}): OsvVuln => ({
  id: "GHSA-x",
  cveId: null,
  summary: "",
  severity: "WARNING",
  fixedVersion: null,
  ...over,
});

describe("compareSemver", () => {
  it("orders versions numerically, not lexically", () => {
    expect(compareSemver("1.9.0", "1.10.0")).toBe(-1); // 9 < 10
    expect(compareSemver("2.0.0", "1.99.99")).toBe(1);
    expect(compareSemver("1.2.3", "1.2.3")).toBe(0);
  });
  it("ignores prerelease/build and a leading v", () => {
    expect(compareSemver("v1.2.3-beta.1", "1.2.3")).toBe(0);
  });
});

describe("fixedVersionFromOsv", () => {
  const affected = [
    {
      package: { ecosystem: "npm", name: "left-pad" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.3.0" }, { fixed: "1.2.0" }] }],
    },
    { package: { ecosystem: "npm", name: "other" }, ranges: [{ events: [{ fixed: "9.9.9" }] }] },
  ];
  it("returns the smallest fixed version for the matching npm package", () => {
    expect(fixedVersionFromOsv(affected, "left-pad")).toBe("1.2.0");
  });
  it("returns null when the package isn't in the affected list", () => {
    expect(fixedVersionFromOsv(affected, "nope")).toBeNull();
  });
  it("returns null on non-array input", () => {
    expect(fixedVersionFromOsv(null, "x")).toBeNull();
  });
});

describe("pickTargetVersion", () => {
  it("picks the highest fixed version to clear all vulns", () => {
    expect(pickTargetVersion([vuln({ fixedVersion: "1.2.0" }), vuln({ fixedVersion: "1.5.0" })])).toBe("1.5.0");
  });
  it("is null when no vuln has a fixed version", () => {
    expect(pickTargetVersion([vuln(), vuln()])).toBeNull();
  });
});

describe("planDependencyBumps", () => {
  // A package installed at two versions yields one target per version; the
  // bump must clear both, so the higher fix wins whatever the order.
  it("bumps to the highest target when one package has several", () => {
    const pkg = JSON.stringify({ dependencies: { "fast-uri": "^3.1.0" } });
    const { updated } = planDependencyBumps(pkg, [{ name: "fast-uri", version: "3.2.0" }, { name: "fast-uri", version: "3.1.5" }]);
    expect(JSON.parse(updated).dependencies["fast-uri"]).toBe("^3.2.0");
  });

  const pkg = JSON.stringify(
    { name: "app", dependencies: { "left-pad": "^1.0.0", react: "19.0.0" }, devDependencies: { vitest: "~4.0.0" } },
    null,
    2
  );

  it("bumps a vulnerable dep and preserves the range operator", () => {
    const { updated, changes } = planDependencyBumps(pkg, [{ name: "left-pad", version: "1.3.0" }]);
    expect(changes).toEqual([{ name: "left-pad", from: "^1.0.0", to: "^1.3.0", section: "dependencies" }]);
    expect(JSON.parse(updated).dependencies["left-pad"]).toBe("^1.3.0");
  });

  it("bumps devDependencies too and keeps the ~ operator", () => {
    const { changes } = planDependencyBumps(pkg, [{ name: "vitest", version: "4.2.0" }]);
    expect(changes[0]).toMatchObject({ to: "~4.2.0", section: "devDependencies" });
  });

  it("never downgrades or touches deps already at/above target", () => {
    expect(planDependencyBumps(pkg, [{ name: "react", version: "18.0.0" }]).changes).toEqual([]);
  });

  it("never rewrites non-semver ranges (workspace/file/git/wildcard)", () => {
    const weird = JSON.stringify(
      { dependencies: { a: "workspace:*", b: "file:../b", c: "*", d: "github:x/y" } },
      null,
      2
    );
    const { changes } = planDependencyBumps(weird, [
      { name: "a", version: "2.0.0" },
      { name: "b", version: "2.0.0" },
      { name: "c", version: "2.0.0" },
      { name: "d", version: "2.0.0" },
    ]);
    expect(changes).toEqual([]);
  });

  it("ignores deps not present and returns original json when nothing changes", () => {
    const { updated, changes } = planDependencyBumps(pkg, [{ name: "absent", version: "1.0.0" }]);
    expect(changes).toEqual([]);
    expect(updated).toBe(pkg);
  });

  it("returns no changes on unparseable package.json", () => {
    expect(planDependencyBumps("not json", [{ name: "x", version: "1.0.0" }]).changes).toEqual([]);
  });
});

describe("buildPrBody", () => {
  it("lists each bump", () => {
    const body = buildPrBody([{ name: "left-pad", from: "^1.0.0", to: "^1.3.0", section: "dependencies" }]);
    expect(body).toContain("left-pad");
    expect(body).toContain("`^1.0.0` → `^1.3.0`");
  });
});
