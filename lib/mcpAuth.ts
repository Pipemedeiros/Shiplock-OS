import { NextRequest, NextResponse } from "next/server";
import { resolveApiToken } from "@/lib/apiTokens";

// Auth for the /api/mcp/* endpoints the MCP server calls: a ShipLock PAT in the
// Authorization header. Resolves to a product-access user_id or an error
// response (401 unknown/invalid, 402 no current profile/access). It does not
// expose the underlying database failure or payment flag.
export async function authMcp(
  req: NextRequest
): Promise<{ userId: string } | { error: NextResponse }> {
  const token = req.headers.get("authorization")?.replace("Bearer ", "").trim();
  if (!token) return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };

  const resolved = await resolveApiToken(token);
  if (!resolved) return { error: NextResponse.json({ error: "Invalid token." }, { status: 401 }) };
  if (!resolved.hasAccess) return { error: NextResponse.json({ error: "Product access unavailable." }, { status: 402 }) };

  return { userId: resolved.userId };
}
