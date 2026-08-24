import { NextResponse } from "next/server";
import { z } from "zod";
import { requireProUser } from "@/lib/deep/proGate";
import {
  connectDirectPostgres,
  disconnectDirectPostgres,
  runDirectPostgresScan,
} from "@/lib/deep/postgresDirectRun";

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
    // Scan immediately, so connecting produces a result rather than a promise
    // that something will happen within 48 hours.
    const scan = await runDirectPostgresScan(pro.userId);
    return NextResponse.json({ ok: true, display: result.display, findings: scan.findings });
  }

  if (parsed.action === "disconnect") {
    await disconnectDirectPostgres(pro.userId);
    return NextResponse.json({ ok: true });
  }

  const result = await runDirectPostgresScan(pro.userId);
  if (!result.ok) {
    const message =
      result.reason === "not_connected"
        ? "Connect your database first."
        : result.reason === "auth_failed"
          ? "Postgres rejected the stored credentials. Reconnect to keep policy checks running."
          : result.reason === "not_read_only"
            ? "That role can write to your database. Reconnect with a read-only role."
            : result.reason === "blocked_host"
              ? "That host is not publicly reachable, so we cannot connect to it."
              : "Couldn't read your policies just now. Try again in a moment.";
    return NextResponse.json({ error: message, reason: result.reason }, { status: 400 });
  }

  return NextResponse.json({ ok: true, findings: result.findings });
}
