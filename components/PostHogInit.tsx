"use client";

// Mounts once in app/(d)/layout.tsx and initialises PostHog on the client.
// Renders nothing. See lib/analytics.ts for the config and the
// no-sensitive-properties rule.

import { useEffect } from "react";
import { initAnalytics } from "@/lib/analytics";

export function PostHogInit() {
  useEffect(() => {
    initAnalytics();
  }, []);
  return null;
}
