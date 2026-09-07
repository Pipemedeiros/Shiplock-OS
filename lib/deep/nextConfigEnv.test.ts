import { describe, expect, it } from "vitest";
import { scanNextConfigEnv } from "./nextConfigEnv";

describe("next.config env entries", () => {
  it("reports a process.env mapping without guessing whether its value is private", () => {
    const findings = scanNextConfigEnv([
      {
        path: "next.config.ts",
        content: `const config = { env: { API_ORIGIN: process.env.INTERNAL_API_ORIGIN } }; export default config;`,
      },
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("github:next_config_env:API_ORIGIN:next.config.ts");
    expect(findings[0].severity).toBe("WARNING");
    expect(findings[0].consequence).toContain("process.env.INTERNAL_API_ORIGIN");
    expect(findings[0].consequence).toContain("JavaScript bundle");
  });

  it("reports a literal only when the value itself is credential evidence", () => {
    const findings = scanNextConfigEnv([
      {
        path: "next.config.mjs",
        content: `export default { env: { LABEL: "internal", API_KEY: "sb_secret_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5" } };`,
      },
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0].id).toBe("github:next_config_env_credential:API_KEY:next.config.mjs");
    expect(findings[0].severity).toBe("CRITICAL");
  });

  it("does not treat a sensitive-looking key name as evidence about a benign literal", () => {
    expect(
      scanNextConfigEnv([
        { path: "next.config.js", content: `module.exports = { env: { SECRET_LABEL: "not-a-credential" } };` },
      ])
    ).toEqual([]);
  });

  it("ignores process.env reads outside the config env object", () => {
    expect(
      scanNextConfigEnv([
        { path: "next.config.ts", content: `const x = process.env.INTERNAL_SECRET; export default { reactStrictMode: true };` },
      ])
    ).toEqual([]);
  });

  it("does not duplicate variables already public by the Next.js convention", () => {
    expect(
      scanNextConfigEnv([
        { path: "next.config.ts", content: `export default { env: { ANALYTICS: process.env.NEXT_PUBLIC_ANALYTICS } };` },
      ])
    ).toEqual([]);
  });

  it("reads only next.config files", () => {
    expect(
      scanNextConfigEnv([
        { path: "lib/config.ts", content: `export default { env: { API: process.env.INTERNAL_API } };` },
      ])
    ).toEqual([]);
  });
  it.each([
    `module.exports = { env: { API: process.env.INTERNAL_API }, env: {} };`,
    `const config = { env: { API: process.env.INTERNAL_API } }; config.env = {}; module.exports = config;`,
    `let config = { env: { API: process.env.INTERNAL_API } }; config = {}; export default config;`,
    `export default { env: { API: process.env.INTERNAL_API, API: "public" } };`,
    `export default { env: { API: process.env.INTERNAL_API }, ...dynamicConfig };`,
    `export default () => ({ env: { API: process.env.INTERNAL_API } });`,
  ])("does not claim exposure for overwritten or unresolved config: %s", (content) => {
    expect(scanNextConfigEnv([{ path: "next.config.js", content }])).toEqual([]);
  });

  it.each([
    `const config = { env: { API: process.env.INTERNAL_API } }; const alias = config; export default alias;`,
    `const config = { env: { API: process.env.INTERNAL_API } }; export { config as default };`,
    `module["exports"] = { ["env"]: { API: process["env"]["INTERNAL_API"] } };`,
    `const vars = { API: process.env.INTERNAL_API }; module.exports = { env: vars };`,
  ])("reads local aliases and literal bracket properties: %s", (content) => {
    expect(scanNextConfigEnv([{ path: "next.config.js", content }])).toHaveLength(1);
  });

  it.each(["VITE_KEY", "PUBLIC_KEY", "EXPO_PUBLIC_KEY", "REACT_APP_KEY", "GATSBY_KEY"])("does not assume %s is public in Next.js", (name) => {
    const [finding] = scanNextConfigEnv([{ path: "next.config.ts", content: `export default {env: {VALUE: process.env.${name}}}` }]);
    expect(finding?.severity).toBe("WARNING");
    expect(finding?.consequence).toContain("Review whether");
  });

  it("does not treat unsupported config filenames as Next.js configuration", () => {
    expect(scanNextConfigEnv([{ path: "next.config.cjs", content: `module.exports = {env: {API: process.env.INTERNAL_API}}` }])).toEqual([]);
  });

  it.each([
    "sk_live_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5",
    "sk-ant-9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5",
    "ghp_9f3Kq7Lm2Xz8Rt4Bn6Vc1Wd5",
    `${Buffer.from('{"alg":"HS256"}').toString("base64url")}.${Buffer.from('{"role":"service_role"}').toString("base64url")}.signature`,
  ])("retains terminal credential evidence in literal config values", (value) => {
    const [finding] = scanNextConfigEnv([{ path: "next.config.ts", content: `export default {env: {TOKEN: ${JSON.stringify(value)}}}` }]);
    expect(finding?.severity).toBe("CRITICAL");
    expect(finding?.consequence).toContain("can appear");
    expect(JSON.stringify(finding)).not.toContain(value);
  });

});
