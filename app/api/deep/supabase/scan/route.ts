import { NextResponse } from "next/server";
import { requireProUser } from "@/lib/deep/proGate";
import { queueCustomerRecheck } from "@/lib/jobs/manualRecheck";

// Queues an on-demand policy recheck (3F-C2c-5). The monitor worker runs the
// read-only policy scan under its lease; this request collects nothing.
export async function POST() {
  const pro = await requireProUser();
  if (!pro) return NextResponse.json({ error: "A subscription is required." }, { status: 402 });

  try {
    await queueCustomerRecheck(pro.userId, "supabase-management");
  } catch {
    // Admission refuses a customer with nothing connected to check.
    return NextResponse.json({ error: "Connect your Supabase project first, then try again." }, { status: 409 });
  }
  return NextResponse.json({ ok: true, status: "queued" }, { status: 202 });
}
