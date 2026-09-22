import { describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";

const resolveApiToken = vi.fn();
vi.mock("@/lib/apiTokens", () => ({ resolveApiToken }));
const { authMcp } = await import("./mcpAuth");

const request = () => new NextRequest("https://shiplock.dev/api/mcp/findings", {
  headers: { authorization: "Bearer shiplock_pat_test_valid_length" },
});

describe("MCP access", () => {
  it("accepts a current preview account", async () => {
    resolveApiToken.mockResolvedValueOnce({ userId: "user-1", hasAccess: true });
    expect(await authMcp(request())).toEqual({ userId: "user-1" });
  });

  it("rejects a resolved token without product access", async () => {
    resolveApiToken.mockResolvedValueOnce({ userId: "user-1", hasAccess: false });
    const result = await authMcp(request());
    expect("error" in result && result.error.status).toBe(402);
  });
});
