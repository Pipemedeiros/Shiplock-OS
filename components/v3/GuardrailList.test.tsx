import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { deriveGuardrails } from "@/lib/guardrails/guardrails";
import { GuardrailList } from "./GuardrailList";

// G1: the founder sees the same rules the PR check enforces and the coding
// agent reads over MCP. No facts is unknown, never "no rules needed".
const route = { path: "/api/orders", file: "app/api/orders/route.ts", methods: ["GET"], tables: ["orders"], authenticated: true,
  machineGated: false, usesServiceRole: false, ownershipFiltered: true, identityReadable: true, ownershipReadable: true, dataReadable: true,
  machineGateReadable: true, serviceRoleReadable: true, identityGap: null, ownershipGap: null, dataGap: null, machineGateGap: null, via: [] } as never;

describe("GuardrailList", () => {
  it("lists each rule in plain words with its route", () => {
    const html = renderToStaticMarkup(<GuardrailList guardrails={deriveGuardrails([route], { repository: "acme/app", commit: null })} />);
    expect(html).toContain("/api/orders");
    expect(html).toContain("Requires a signed-in caller");
    expect(html).toContain("Rows scoped to the caller");
    expect(html).toMatch(/pull request check blocks/i);
    expect(html.replace(/<[^>]+>/g, " ")).not.toMatch(/[–—]/);
  });

  it("says unknown when no audit facts exist", () => {
    expect(renderToStaticMarkup(<GuardrailList guardrails={null} />)).toMatch(/not known yet/);
  });
});
