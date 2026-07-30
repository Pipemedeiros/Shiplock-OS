import { describe, expect, it } from "vitest";
import {
  assertProvingTarget,
  canProve,
  ProvingGroundViolation,
  type CustomerAutonomySettings,
  type ProvingTarget,
} from "./guard";

const branch = (over: Partial<ProvingTarget> = {}): ProvingTarget => ({
  ref: "branch-abc",
  parentRef: "prod-xyz",
  isEphemeralBranch: true,
  containsProductionData: false,
  ...over,
});

const settings = (over: Partial<CustomerAutonomySettings> = {}): CustomerAutonomySettings => ({
  killSwitchOn: false,
  provingGroundEnabled: true,
  ...over,
});

describe("assertProvingTarget", () => {
  it("permits a verified ephemeral branch for an opted-in customer", () => {
    expect(() => assertProvingTarget(branch(), settings())).not.toThrow();
  });

  it("refuses a missing target", () => {
    expect(() => assertProvingTarget(null, settings())).toThrow(ProvingGroundViolation);
    expect(() => assertProvingTarget(undefined, settings())).toThrow(/No proving target/);
  });

  // The doctrine in one test: production is never a valid target.
  it("refuses anything not created as an ephemeral branch", () => {
    expect(() => assertProvingTarget(branch({ isEphemeralBranch: false }), settings())).toThrow(
      /not an ephemeral branch/
    );
  });

  // The mistake that actually happens: an upstream bug hands us the production
  // ref while still claiming branch status.
  it("refuses when the target ref equals the production ref, even if flagged as a branch", () => {
    expect(() =>
      assertProvingTarget(branch({ ref: "prod-xyz", parentRef: "prod-xyz" }), settings())
    ).toThrow(/This is production/);
  });

  it("refuses a target marked as holding production data", () => {
    expect(() => assertProvingTarget(branch({ containsProductionData: true }), settings())).toThrow(
      /data-less replica/
    );
  });

  it("refuses an empty or malformed ref", () => {
    expect(() => assertProvingTarget(branch({ ref: "" }), settings())).toThrow();
    expect(() =>
      assertProvingTarget(branch({ ref: null as unknown as string }), settings())
    ).toThrow();
  });

  it("honours the per-customer kill switch", () => {
    expect(() => assertProvingTarget(branch(), settings({ killSwitchOn: true }))).toThrow(/kill switch/);
  });

  it("refuses without an explicit opt-in — it never runs by default", () => {
    expect(() => assertProvingTarget(branch(), settings({ provingGroundEnabled: false }))).toThrow(
      /explicit opt-in/
    );
  });

  it("refuses when the kill switch is on even for a perfectly valid branch", () => {
    expect(() =>
      assertProvingTarget(branch(), settings({ killSwitchOn: true, provingGroundEnabled: true }))
    ).toThrow(ProvingGroundViolation);
  });

  // There must be no way to say "yes I know, do it anyway".
  it("has no override: every rejection path throws the same violation type", () => {
    const rejections: [ProvingTarget | null, CustomerAutonomySettings][] = [
      [null, settings()],
      [branch({ isEphemeralBranch: false }), settings()],
      [branch({ ref: "prod-xyz" }), settings()],
      [branch({ containsProductionData: true }), settings()],
      [branch(), settings({ killSwitchOn: true })],
      [branch(), settings({ provingGroundEnabled: false })],
    ];
    for (const [target, s] of rejections) {
      expect(() => assertProvingTarget(target, s)).toThrow(ProvingGroundViolation);
    }
  });

  it("names the production ref in the error, so the incident is diagnosable", () => {
    expect(() => assertProvingTarget(branch({ ref: "prod-xyz" }), settings())).toThrow(/prod-xyz/);
  });
});

describe("canProve", () => {
  it("agrees with the assert on every case", () => {
    expect(canProve(branch(), settings())).toBe(true);
    expect(canProve(branch({ isEphemeralBranch: false }), settings())).toBe(false);
    expect(canProve(branch({ ref: "prod-xyz" }), settings())).toBe(false);
    expect(canProve(null, settings())).toBe(false);
    expect(canProve(branch(), settings({ killSwitchOn: true }))).toBe(false);
    expect(canProve(branch(), settings({ provingGroundEnabled: false }))).toBe(false);
  });

  it("never throws", () => {
    expect(() => canProve(null, settings())).not.toThrow();
  });
});
