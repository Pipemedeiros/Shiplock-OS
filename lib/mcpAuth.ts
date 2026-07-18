import { NextRequest, NextResponse } from "next/server";
import { resolveApiToken } from "@/lib/apiTokens";

// Auth for the /api/mcp/* endpoints the MCP server calls: a ShipLock PAT in the
// Authorization header. Resolves to a paid user_id or a ready-to-return error
// response (401 unknown/invalid, 402 unpaid). Never leaks which case it is
// beyond the status.
export async function authMcp(
  req: NextRequest
): Promise<{ userId: string } | { error: NextResponse }> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "").trim();
  if (!token) return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };

  const resolved = await resolveApiToken(token);
  if (!resolved) return { error: NextResponse.json({ error: "Invalid token." }, { status: 401 }) };
  if (!resolved.isPaid) return { error: NextResponse.json({ error: "A subscription is required." }, { status: 402 }) };

  return { userId: resolved.userId };
}
