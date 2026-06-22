import { createClient, SupabaseClient } from "@supabase/supabase-js";

// Singleton browser client — safe to call from any "use client" component.
// Uses the public anon key; relies on Supabase RLS for row-level access control.
let _client: SupabaseClient | null = null;

export function getSupabaseBrowser(): SupabaseClient {
  if (!_client) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    if (!url || !key) {
      throw new Error("NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY must be set in environment variables");
    }
    _client = createClient(url, key);
  }
  return _client;
}
