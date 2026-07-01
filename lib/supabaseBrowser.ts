import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";

// Singleton browser client — safe to call from any "use client" component.
// Uses createBrowserClient (not the plain @supabase/supabase-js client) so
// the session is stored in cookies rather than localStorage, keeping it in
// sync with the server client and middleware. Required for the OAuth PKCE
// flow: the code verifier and resulting session must be readable by the
// server-side callback route, not just the browser tab that started it.
let _client: SupabaseClient | null = null;

export function getSupabaseBrowser(): SupabaseClient {
  if (!_client) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
    const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
    if (!url || !key) {
      throw new Error("NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY must be set in environment variables");
    }
    _client = createBrowserClient(url, key);
  }
  return _client;
}
