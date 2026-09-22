import { NextResponse } from "next/server";

// Keep the old endpoint closed until pricing and billing are deliberately rebuilt.
export async function POST() {
  return NextResponse.json(
    { error: "Billing is not available during the preview." },
    { status: 503 }
  );
}
