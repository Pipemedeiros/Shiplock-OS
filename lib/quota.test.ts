import { describe, expect, it } from "vitest";
import { quotaCode, quotaResponse } from "./quota";

describe("provisional quotas speak plainly", () => {
  it("recognizes each database quota refusal", () => {
    expect(quotaCode("audit quota reached")).toBe("audit_quota_reached");
    expect(quotaCode("ERROR: recheck quota reached")).toBe("recheck_quota_reached");
    expect(quotaCode("repair quota reached")).toBe("repair_quota_reached");
    expect(quotaCode("token limit reached")).toBe("token_limit_reached");
    expect(quotaCode("queue capacity reached")).toBeNull();
  });

  it("turns a quota error into a 429 with a plain message, and anything else into null", async () => {
    for (const code of ["audit_quota_reached", "recheck_quota_reached", "repair_quota_reached", "token_limit_reached"]) {
      const response = quotaResponse(new Error(code));
      expect(response?.status).toBe(429);
      const { error } = await response!.json();
      expect(error).toMatch(/limit/);
      expect(error).not.toMatch(/[—–]/);
    }
    expect(quotaResponse(new Error("private detail"))).toBeNull();
    expect(quotaResponse("x")).toBeNull();
  });
});
