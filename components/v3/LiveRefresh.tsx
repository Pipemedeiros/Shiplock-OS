"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/**
 * Re-reads the page while something it shows is still happening (an audit
 * queued or running), so the customer watches it progress. Stops on its own
 * once the server renders the page with `active` false; skips hidden tabs.
 */
export function LiveRefresh({ active, everyMs = 5_000 }: { active: boolean; everyMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => { if (!document.hidden) router.refresh(); }, everyMs);
    return () => window.clearInterval(timer);
  }, [active, everyMs, router]);
  return null;
}
