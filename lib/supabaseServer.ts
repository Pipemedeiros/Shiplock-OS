import { cookies } from "next/headers";
import { createServerClient } from "@supabase/ssr";

// Per-request server-side client (Server Components, Route Handlers, Server
// Actions) — reads/writes the session via cookies so SSR pages and the
// OAuth callback see the same auth state as the browser client. Relies on
// RLS for access control; never bypasses it (that's getSupabaseAdmin()).
export async function getSupabaseServer() {
  const cookieStore = await cookies();
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  if (!url || !key) {
    throw new Error("NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY must be set");
  }

  return createServerClient(url, key, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          cookiesToSet.forEach(({ name, value, options }) =>
            cookieStore.set(name, value, options)
          );
        } catch {
          // Called from a Server Component that can't set cookies — the
          // middleware's own session refresh already handles this case.
        }
      },
    },
  });
}
