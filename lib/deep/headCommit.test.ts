import { afterEach, expect, it, vi } from "vitest";
import { getHeadCommit } from "./headCommit";

afterEach(() => vi.unstubAllGlobals());
const sha = "c".repeat(40);
const ref = (s: string) => new Response(JSON.stringify({ object: { sha: s } }), { status: 200 });

it("resolves the stored default branch to its commit with one call", async () => {
  const fetchMock = vi.fn().mockResolvedValueOnce(ref(sha));
  vi.stubGlobal("fetch", fetchMock);
  expect(await getHeadCommit("t", "acme/app", "main")).toBe(sha);
  expect(fetchMock).toHaveBeenCalledOnce();
  expect(fetchMock.mock.calls[0][0]).toContain("/repos/acme/app/git/ref/heads/main");
});

it("follows a renamed default branch instead of failing every audit", async () => {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response("{}", { status: 404 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ default_branch: "trunk" }), { status: 200 }))
    .mockResolvedValueOnce(ref(sha));
  vi.stubGlobal("fetch", fetchMock);
  expect(await getHeadCommit("t", "acme/app", "main")).toBe(sha);
  expect(fetchMock.mock.calls[1][0]).toMatch(/\/repos\/acme\/app$/);
  expect(fetchMock.mock.calls[2][0]).toContain("/git/ref/heads/trunk");
});

it("fails loudly when the repository cannot be read at all", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 404 })));
  await expect(getHeadCommit("t", "acme/app", "main")).rejects.toThrow();
});
