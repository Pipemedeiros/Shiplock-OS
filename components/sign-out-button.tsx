"use client";

import { useState } from "react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";

export function SignOutButton() {
  const [loading, setLoading] = useState(false);

  async function handleSignOut() {
    setLoading(true);
    const supabase = getSupabaseBrowser();
    await supabase.auth.signOut();
    // Temporary: "/" is the correct long-term destination, but production's
    // real landing page isn't deployed yet (still uncommitted WIP) — it
    // currently serves the default Next.js scaffold. Redirect to /auth
    // instead until that ships, then switch this back to "/".
    window.location.href = "/auth";
  }

  return (
    <Button
      type="button"
      variant="outline"
      disabled={loading}
      onClick={handleSignOut}
      className="h-9 gap-2 rounded-lg border-[#1f2937] bg-transparent text-[13px] font-medium text-white hover:bg-white/5"
    >
      {loading && <Loader2 className="size-3.5 animate-spin" />}
      Sign out
    </Button>
  );
}
