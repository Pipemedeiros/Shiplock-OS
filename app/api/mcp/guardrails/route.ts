import { NextRequest, NextResponse } from "next/server";
import { authMcp } from "@/lib/mcpAuth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { loadRepositoryGraphSource } from "@/lib/graph/repositorySource";
import { deriveGuardrails } from "@/lib/guardrails/guardrails";

// MCP `get_guardrails` (G1): the security properties a selected repository has
// today, as the rules the PR check enforces. Read only, PAT authenticated.
// Built from the last audit's stored route facts (at most 60 routes); a
// control ShipLock could not read is never a rule, and no facts is "unknown".
export async function GET(req: NextRequest) {
  const ctx = await authMcp(req);
  if ("error" in ctx) return ctx.error;

  const { data: selected, error } = await getSupabaseAdmin()
    .from("repositories").select("id, full_name").eq("user_id", ctx.userId).eq("selected", true);
  if (error) return NextResponse.json({ error: "Repositories could not be read." }, { status: 503 });
  const list = (selected ?? []) as { id: string; full_name: string }[];

  const named = req.nextUrl.searchParams.get("repository");
  const repository = named ? list.find((r) => r.full_name === named) : list.length === 1 ? list[0] : undefined;
  if (!repository) {
    return named
      ? NextResponse.json({ error: "That repository is not selected in ShipLock." }, { status: 404 })
      : NextResponse.json({ error: "Name a repository.", repositories: list.map((r) => r.full_name) }, { status: 400 });
  }

  const source = await loadRepositoryGraphSource(ctx.userId, repository.id);
  if (!source.routes) {
    return NextResponse.json({ repository: repository.full_name, guardrails: null,
      coverage: "No audit facts are stored for this repository yet, so its guardrails are unknown. Run an audit first." });
  }
  return NextResponse.json({
    repository: repository.full_name,
    guardrails: deriveGuardrails(source.routes, { repository: repository.full_name, commit: null }),
    coverage: "From the last audit's route facts (up to 60 routes). Controls we could not read are not rules, so a route without a rule is not known to be safe.",
  });
}
