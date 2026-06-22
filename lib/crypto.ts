import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

const ALGORITHM  = "aes-256-gcm";
const IV_LENGTH  = 12;
const TAG_LENGTH = 16;

function getKey(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) throw new Error("ENCRYPTION_KEY env var is not set");
  const buf = Buffer.from(raw, "base64");
  if (buf.length !== 32) throw new Error("ENCRYPTION_KEY must decode to exactly 32 bytes (use: openssl rand -base64 32)");
  return buf;
}

// Returns base64-encoded: iv (12 bytes) + authTag (16 bytes) + ciphertext
export function encrypt(plaintext: string): string {
  const key    = getKey();
  const iv     = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag       = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

export function decrypt(ciphertext: string): string {
  const key  = getKey();
  const data = Buffer.from(ciphertext, "base64");
  const iv        = data.subarray(0, IV_LENGTH);
  const tag       = data.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const encrypted = data.subarray(IV_LENGTH + TAG_LENGTH);
  const decipher  = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}
