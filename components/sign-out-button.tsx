"use client";

import { useState } from "react";
import { Loader2 } from "lucide-react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

export function SignOutButton() {
  const [loading, setLoading] = useState(false);

  async function handleSignOut() {
    setLoading(true);
    const supabase = getSupabaseBrowser();
    await supabase.auth.signOut();
    window.location.href = "/";
  }

  return (
    <button
      type="button"
      disabled={loading}
      onClick={handleSignOut}
      className="v3-btn v3-btn-sm v3-ghost"
    >
      {loading && <Loader2 className="size-3.5 animate-spin" />}
      Sign out
    </button>
  );
}
