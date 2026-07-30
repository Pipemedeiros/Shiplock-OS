import { getSupabaseAdmin } from "@/lib/supabase";
import { summariseExposure, type ExposureSummary, type TableInventory } from "./model";

// Reads the A21 inventory the database collector stored and turns it into the
// exposure summary the dashboard renders.
//
// Returns null when there is no inventory — the collector has not run, or
// Supabase is not connected. The panel renders nothing at all in that case,
// rather than a zero, because "$0 of exposure" and "we have not looked" are
// completely different statements and only one of them is true.
export async function loadExposure(userId: string): Promise<ExposureSummary | null> {
  try {
    const { data } = await getSupabaseAdmin()
      .from("graph_facts")
      .select("facts")
      .eq("user_id", userId)
      .eq("collector", "db")
      .maybeSingle();

    const inventory = (data?.facts as { inventory?: TableInventory[] } | null)?.inventory;
    if (!Array.isArray(inventory) || inventory.length === 0) return null;

    return summariseExposure(inventory);
  } catch {
    return null;
  }
}
