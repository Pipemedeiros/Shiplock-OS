import { describe, expect, it } from "vitest";
import { scanSecrets } from "@/lib/deep/githubScan";
import { scanNextConfigEnv } from "@/lib/deep/nextConfigEnv";
import { scanPublicCredentialValues } from "@/lib/deep/clientExposure";
import { scanCredentialHandling } from "@/lib/deep/credentialHandling";
import { deterministicFindings } from "./deterministicFindings";

// One list of the checks an audit runs with no agent, shared by the audit and
// the offline harness (scripts/corpus.cjs shown), so a measurement of what a
// founder sees cannot drift from what production shows.
describe("deterministicFindings", () => {
  const files = [
    { path: ".env.save", content: "DATABASE_URL=postgresql://app:s3cretpassw0rd@ep-x.us-east-2.aws.neon.tech/db\n" },
    { path: "next.config.js", content: "module.exports = { env: { NEXTAUTH_SECRET: process.env.NEXTAUTH_SECRET } };\n" },
    { path: "lib/otp.ts", content: "export const otp = Math.floor(100000 + Math.random() * 900000);\n" },
    { path: "lib/call.ts", content: "fetch(`https://api.example.com/x?api_key=${key}`);\n" },
  ];
  it("is exactly the four scanners the audit runs, in order", () => {
    expect(deterministicFindings(files)).toEqual([
      ...scanSecrets(files), ...scanNextConfigEnv(files), ...scanPublicCredentialValues(files), ...scanCredentialHandling(files),
    ]);
    expect(deterministicFindings(files).length).toBeGreaterThan(0);
  });
});
