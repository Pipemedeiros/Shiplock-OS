import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { AgentSetupView, codexHttpConfig, httpCommand, setupCommand } from "./AgentSetup";

const base = { tokens: [], fresh: null, busy: false, error: "", onGenerate: vi.fn(), onRevoke: vi.fn(), published: true };
const html = (props: Partial<Parameters<typeof AgentSetupView>[0]> & { host: Parameters<typeof AgentSetupView>[0]["host"] }) =>
  renderToStaticMarkup(AgentSetupView({ ...base, ...props }));

describe("AgentSetup (MCP for every account)", () => {
  it("gives Claude Code and Codex the exact setup for the published package", () => {
    expect(setupCommand("claude-code", "tok")).toBe("claude mcp add shiplock --env SHIPLOCK_TOKEN=tok -- npx -y shiplock-mcp");
    expect(setupCommand("codex", "tok")).toContain('[mcp_servers.shiplock]');
    expect(setupCommand("codex", "tok")).toContain('args = ["-y", "shiplock-mcp"]');
    expect(setupCommand("codex", "tok")).toContain('SHIPLOCK_TOKEN = "tok"');
  });

  it("shows a fresh token once with its command, and warns it will not be shown again", () => {
    const out = html({ host: "claude-code", fresh: "shiplock_pat_abc" });
    expect(out).toContain("claude mcp add shiplock --env SHIPLOCK_TOKEN=shiplock_pat_abc");
    expect(out).toContain("shown only once");
  });

  it("is honest about what a connected agent does and does not do", () => {
    const out = html({ host: "codex" });
    expect(html({ host: "claude-code", published: false })).toContain("cannot start your agent");
    expect(out).toContain("when you run it");
    expect(out).toContain("cannot start your agent");
    expect(out).toContain("never merges");
    expect(out).not.toMatch(/applies the fixes|automatically fix/i);
  });

  // The hosted endpoint (app/api/mcp/server) needs no npm package, so
  // Claude Code and Codex (streamable HTTP, url + bearer_token_env_var in the
  // official Codex docs, read 2026-10-20) both connect today.
  it("connects Claude Code over HTTP with no package, and the token in a header", () => {
    expect(httpCommand("https://shiplock.dev", "tok")).toBe('claude mcp add --transport http shiplock https://shiplock.dev/api/mcp/server --header "Authorization: Bearer tok"');
    const out = html({ host: "claude-code", published: false, fresh: "tok", origin: "https://shiplock.dev" });
    expect(out).toContain("Create a token");
    expect(out).toContain("claude mcp add --transport http shiplock https://shiplock.dev/api/mcp/server");
    expect(out).not.toContain("npx");
  });

  it("connects Codex over HTTP with no package, the token only in the environment", () => {
    expect(codexHttpConfig("https://shiplock.dev/")).toBe('[mcp_servers.shiplock]\nurl = "https://shiplock.dev/api/mcp/server"\nbearer_token_env_var = "SHIPLOCK_TOKEN"');
    const out = html({ host: "codex", published: false, fresh: "tok", origin: "https://shiplock.dev" });
    expect(out).toContain("Create a token");
    expect(out).toContain("url = &quot;https://shiplock.dev/api/mcp/server&quot;");
    expect(out).toContain("export SHIPLOCK_TOKEN=tok");
    expect(out).not.toContain("SHIPLOCK_TOKEN = &quot;tok&quot;");
    expect(out).not.toContain("npx");
  });

  it("says ChatGPT is not available yet and offers no token", () => {
    const out = html({ host: "chatgpt" });
    expect(out).toContain("ChatGPT connection is not available yet");
    expect(out).not.toContain("Create a token");
  });

  it("lists active tokens by name only with a revoke control", () => {
    const out = html({ host: "claude-code", tokens: [{ id: "t1", name: "MCP token", created_at: "2026-09-23T00:00:00Z", last_used_at: null }] });
    expect(out).toContain("MCP token");
    expect(out).toContain("Revoke");
    expect(out).not.toContain("shiplock_pat_");
  });
});
