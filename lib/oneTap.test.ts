import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { GOOGLE_CLIENT_ID, makeNonce } from "./oneTap";

// Google One Tap: a fresh random nonce per prompt; Google gets its SHA-256 hex,
// Supabase gets the raw value and checks the ID token carries the hash.
describe("One Tap nonce", () => {
  it("is random, 32 bytes, and Google's copy is its SHA-256 hex", async () => {
    const [raw, hashed] = await makeNonce();
    const [other] = await makeNonce();
    expect(raw).not.toBe(other);
    expect(Buffer.from(raw, "base64")).toHaveLength(32);
    expect(hashed).toBe(createHash("sha256").update(raw).digest("hex"));
  });

  it("uses the public web client id the Google provider already uses", () => {
    expect(GOOGLE_CLIENT_ID).toMatch(/^\d+-[a-z0-9]+\.apps\.googleusercontent\.com$/);
  });
});
