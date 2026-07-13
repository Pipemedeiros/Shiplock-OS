"use client";

import { useState } from "react";
import { Loader2 } from "lucide-react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { track } from "@/lib/analytics";

type OAuthProvider = "google" | "github";

function GoogleMark() {
  return (
    <svg viewBox="0 0 24 24" className="size-4 shrink-0" fill="currentColor" aria-hidden>
      <path d="M21.35 11.1h-9.17v2.95h5.4c-.23 1.45-1.68 4.25-5.4 4.25-3.25 0-5.9-2.7-5.9-6s2.65-6 5.9-6c1.85 0 3.09.79 3.8 1.47l2.59-2.5C16.96 3.6 14.9 2.7 12.18 2.7 6.98 2.7 2.75 6.93 2.75 12.15s4.23 9.45 9.43 9.45c5.44 0 9.05-3.82 9.05-9.2 0-.62-.07-1.09-.15-1.3Z" />
    </svg>
  );
}

function GitHubMark() {
  return (
    <svg viewBox="0 0 24 24" className="size-4 shrink-0" fill="currentColor" aria-hidden>
      <path
        fillRule="evenodd"
        clipRule="evenodd"
        d="M12 2C6.48 2 2 6.58 2 12.2c0 4.5 2.87 8.31 6.84 9.66.5.1.68-.22.68-.5 0-.24-.01-1.04-.01-1.88-2.78.62-3.37-1.24-3.37-1.24-.45-1.18-1.11-1.5-1.11-1.5-.9-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05a9.29 9.29 0 0 1 5 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.79-4.57 5.05.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.6.69.5A9.96 9.96 0 0 0 22 12.2C22 6.58 17.52 2 12 2Z"
      />
    </svg>
  );
}

// Real OAuth sign-in — same signInWithOAuth call as components/auth-form.tsx,
// restyled for the light marketing design system. Clicking either button
// starts a genuine Google/GitHub sign-in, not a mock.
export function OAuthButtons() {
  const [loading, setLoading] = useState<OAuthProvider | null>(null);
  const [error, setError] = useState("");

  async function handleOAuth(provider: OAuthProvider) {
    track("auth_started", { provider });
    setError("");
    setLoading(provider);
    const supabase = getSupabaseBrowser();
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: `${window.location.origin}/auth/callback` },
    });
    if (error) {
      setError(error.message);
      setLoading(null);
    }
  }

  return (
    <div className="flex w-full max-w-sm flex-col gap-3">
      <button
        type="button"
        disabled={loading !== null}
        onClick={() => handleOAuth("google")}
        className="flex h-12 w-full items-center justify-center gap-2.5 rounded-lg border border-border bg-white text-sm font-medium text-foreground shadow-sm transition-colors hover:bg-secondary disabled:opacity-60"
      >
        {loading === "google" ? <Loader2 className="size-4 animate-spin" /> : <GoogleMark />}
        Continue with Google
      </button>
      <button
        type="button"
        disabled={loading !== null}
        onClick={() => handleOAuth("github")}
        className="flex h-12 w-full items-center justify-center gap-2.5 rounded-lg border border-border bg-white text-sm font-medium text-foreground shadow-sm transition-colors hover:bg-secondary disabled:opacity-60"
      >
        {loading === "github" ? <Loader2 className="size-4 animate-spin" /> : <GitHubMark />}
        Continue with GitHub
      </button>
      {error && <p className="text-[13px] text-sev-critical">{error}</p>}
    </div>
  );
}
