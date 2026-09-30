"use client";

import { useEffect } from "react";
import { GOOGLE_CLIENT_ID, makeNonce } from "@/lib/oneTap";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

// Google's corner "Sign in to shiplock.dev with google.com" prompt (Felipe
// 2026-09-30). Shown only to signed-out visitors; Google itself decides when
// to show it (cool-down after a dismissal, FedCM in Chrome). The ID token is
// exchanged with Supabase with a per-prompt nonce; nothing is stored here.
type Credential = { credential: string };
type GoogleId = {
  initialize(options: Record<string, unknown>): void;
  prompt(): void;
  cancel(): void;
};
declare global { interface Window { google?: { accounts: { id: GoogleId } } } }

const SCRIPT = "https://accounts.google.com/gsi/client";

function loadScript(): Promise<void> {
  if (window.google?.accounts?.id) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = SCRIPT;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Google sign-in did not load"));
    document.head.appendChild(script);
  });
}

export function GoogleOneTap({ next = "/dashboard" }: { next?: string }) {
  useEffect(() => {
    let cancelled = false;
    const supabase = getSupabaseBrowser();
    (async () => {
      const { data } = await supabase.auth.getSession();
      if (data.session || cancelled) return;
      const [raw, hashed] = await makeNonce();
      try { await loadScript(); } catch { return; /* Google unreachable: the buttons still work */ }
      if (cancelled || !window.google) return;
      window.google.accounts.id.initialize({
        client_id: GOOGLE_CLIENT_ID,
        nonce: hashed,
        context: "signin",
        use_fedcm_for_prompt: true,
        itp_support: true,
        cancel_on_tap_outside: false,
        callback: async ({ credential }: Credential) => {
          const { error } = await supabase.auth.signInWithIdToken({ provider: "google", token: credential, nonce: raw });
          if (error) {
            window.location.assign(`/auth?error=oauth_failed&next=${encodeURIComponent(next)}`);
            return;
          }
          await fetch("/api/auth/welcome", { method: "POST" }).catch(() => undefined);
          window.location.assign(next);
        },
      });
      window.google.accounts.id.prompt();
    })();
    return () => { cancelled = true; window.google?.accounts?.id?.cancel(); };
  }, [next]);

  return null;
}
