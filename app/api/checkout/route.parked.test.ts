import { describe, expect, it } from "vitest";

const { POST } = await import("./route");

describe("POST /api/checkout while pricing is undecided", () => {
  it("keeps checkout closed while pricing is undecided", async () => {
    const response = await POST();

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "Billing is not available during the preview.",
    });
  });
});
