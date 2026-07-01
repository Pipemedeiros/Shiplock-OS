"use client";

import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

type Mode = "sign-in" | "sign-up";
type OAuthProvider = "google" | "github";

// Minimal monochrome marks — intentionally not the providers' full-color
// branded icons, to match the app's outlined, low-noise button style.
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

export function AuthForm({ oauthError = false }: { oauthError?: boolean }) {
  const [mode, setMode] = useState<Mode>("sign-in");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [oauthLoading, setOauthLoading] = useState<OAuthProvider | null>(null);
  const [error, setError] = useState(
    oauthError ? "Sign-in with that provider didn't go through. Try again." : ""
  );
  const [notice, setNotice] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setNotice("");
    setLoading(true);
    const supabase = getSupabaseBrowser();

    try {
      if (mode === "sign-in") {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) {
          setError(
            error.message === "Invalid login credentials"
              ? "Incorrect email or password."
              : error.message
          );
          return;
        }
        window.location.href = "/dashboard";
      } else {
        const { error } = await supabase.auth.signUp({ email, password });
        if (error) {
          setError(error.message);
          return;
        }
        setNotice("Check your email to confirm your account, then sign in.");
        setMode("sign-in");
      }
    } catch {
      setError("Couldn't reach the server. Try again in a moment.");
    } finally {
      setLoading(false);
    }
  }

  async function handleOAuth(provider: OAuthProvider) {
    setError("");
    setOauthLoading(provider);
    const supabase = getSupabaseBrowser();
    const { error } = await supabase.auth.signInWithOAuth({
      provider,
      options: { redirectTo: `${window.location.origin}/auth/callback` },
    });
    // On success the browser navigates away immediately; an error here
    // means the redirect never started.
    if (error) {
      setError(error.message);
      setOauthLoading(null);
    }
  }

  return (
    <div className="w-full max-w-[380px] rounded-2xl border border-[#1f2937] bg-[#080808] p-8">
      <h1 className="text-center text-xl font-semibold text-white">
        {mode === "sign-in" ? "Sign in" : "Create your account"}
      </h1>

      <div className="mt-6 flex flex-col gap-2.5">
        <Button
          type="button"
          variant="outline"
          disabled={oauthLoading !== null}
          onClick={() => handleOAuth("google")}
          className="h-11 w-full gap-2.5 rounded-lg border-[#1f2937] bg-transparent text-[14px] font-medium text-white hover:bg-white/5"
        >
          {oauthLoading === "google" ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <GoogleMark />
          )}
          Continue with Google
        </Button>
        <Button
          type="button"
          variant="outline"
          disabled={oauthLoading !== null}
          onClick={() => handleOAuth("github")}
          className="h-11 w-full gap-2.5 rounded-lg border-[#1f2937] bg-transparent text-[14px] font-medium text-white hover:bg-white/5"
        >
          {oauthLoading === "github" ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <GitHubMark />
          )}
          Continue with GitHub
        </Button>
      </div>

      <div className="my-6 flex items-center gap-3">
        <div className="h-px flex-1 bg-[#1f2937]" />
        <span className="text-[11px] uppercase text-[#4b5563]" style={{ letterSpacing: "0.08em" }}>
          or
        </span>
        <div className="h-px flex-1 bg-[#1f2937]" />
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <Input
          type="email"
          required
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          disabled={loading}
          autoComplete="email"
          className="h-11 rounded-lg border-[#1f2937] bg-transparent px-4 text-[14px] text-white shadow-none placeholder:text-[#52525b]"
        />
        <Input
          type="password"
          required
          minLength={6}
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={loading}
          autoComplete={mode === "sign-in" ? "current-password" : "new-password"}
          className="h-11 rounded-lg border-[#1f2937] bg-transparent px-4 text-[14px] text-white shadow-none placeholder:text-[#52525b]"
        />

        {error && <p className="text-[13px] text-[#ef4444]">{error}</p>}
        {notice && <p className="text-[13px] text-[#22c55e]">{notice}</p>}

        <Button
          type="submit"
          disabled={loading}
          className="mt-1 h-11 rounded-lg bg-[#3b82f6] text-[14px] font-medium text-white hover:bg-[#2f6fd8]"
        >
          {loading ? (
            <Loader2 className="size-4 animate-spin" />
          ) : mode === "sign-in" ? (
            "Sign in"
          ) : (
            "Create account"
          )}
        </Button>
      </form>

      <p className="mt-6 text-center text-[13px] text-[#71717a]">
        {mode === "sign-in" ? "Don't have an account? " : "Already have an account? "}
        <button
          type="button"
          onClick={() => {
            setMode(mode === "sign-in" ? "sign-up" : "sign-in");
            setError("");
            setNotice("");
          }}
          className="text-[#3b82f6] hover:underline"
        >
          {mode === "sign-in" ? "Sign up" : "Sign in"}
        </button>
      </p>
    </div>
  );
}
