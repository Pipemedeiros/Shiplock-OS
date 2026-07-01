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
    window.location.href = "/";
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
