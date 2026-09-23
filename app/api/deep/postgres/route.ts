import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import { connectDirectPostgres, disconnectDirectPostgres } from "@/lib/deep/postgresDirectRun";
import { queueCustomerRecheck } from "@/lib/jobs/manualRecheck";
import { crossSiteRefusal } from "@/lib/security/sameOrigin";

// Connect / scan / disconnect a customer's own Postgres, for everyone not on
// Supabase. Same "your database" slot as app/api/deep/supabase/* — a customer
// uses one or the other, and the friction budget stays at two connections.
//
// The connection string arrives in a POST body and is encrypted before it
// touches storage. It is never echoed back, never logged, and never returned by
// any GET: `postgres_display` exists precisely so the dashboard can show a
// connection without the credential going near a page render.

const ConnectBody = z.object({
  action: z.literal("connect"),
  // Bounded here as well as in the parser — a route should not hand an unbounded
  // string to anything, even a parser we control.
  connectionString: z.string().min(1).max(2048),
});

const SimpleBody = z.object({ action: z.enum(["scan", "disconnect"]) });

const Body = z.union([ConnectBody, SimpleBody]);

export async function POST(request: Request) {
  // Cookie-authenticated mutation: require ShipLock's own page as the origin.
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const pro = await requireProUser();
  if (!pro) return NextResponse.json({ error: "A subscription is required." }, { status: 402 });

  let parsed;
  try {
    parsed = Body.parse(await request.json());
  } catch {
    return NextResponse.json({ error: "Invalid request." }, { status: 400 });
  }

  if (parsed.action === "connect") {
    const result = await connectDirectPostgres(pro.userId, parsed.connectionString);
    if (!result.ok) {
      // These messages are the customer's only guide to fixing a bad role or a
      // blocked host, so they are passed through verbatim — they are written to
      // be actionable and contain no credential.
      return NextResponse.json({ error: result.message, reason: result.code }, { status: 400 });
    }
    // Queue the first read now, so connecting produces a result within minutes
    // rather than at the next 48-hour pass. The connection stands even if the
    // queue is briefly unavailable; the scheduled pass will still pick it up.
    const status = await queueCustomerRecheck(pro.userId, "postgres-direct").then(() => "queued", () => "not_queued");
    return NextResponse.json({ ok: true, display: result.display, status });
  }

  if (parsed.action === "disconnect") {
    await disconnectDirectPostgres(pro.userId);
    return NextResponse.json({ ok: true });
  }

  try {
    await queueCustomerRecheck(pro.userId, "postgres-direct");
  } catch {
    // Admission refuses a customer with nothing connected to check.
    return NextResponse.json({ error: "Connect your database first, then try again." }, { status: 409 });
  }
  return NextResponse.json({ ok: true, status: "queued" }, { status: 202 });
}
