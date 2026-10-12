"use client";

// Thin client-side wrapper around posthog-js (and Google Analytics, see
// ./googleAnalytics.ts). Initialised only after the
// visitor accepts analytics cookies (components/CookieConsent.tsx); everything
// else calls track() and never touches posthog directly. Rules:
// - Never put keys, URLs, emails, or scan content in properties — counts,
//   counts and booleans only. The privacy page describes PostHog as
//   product-usage analytics; keep it true.
// - No key configured (local dev) → everything silently no-ops.

import posthog from "posthog-js";
import { startGoogleAnalytics } from "./googleAnalytics";

let initialised = false;

export function initAnalytics(): void {
  if (initialised || typeof window === "undefined") return;
  // Google Analytics: visit counts, same consent; a no-op without its id.
  startGoogleAnalytics(document as unknown as Parameters<typeof startGoogleAnalytics>[0],
    window as unknown as Parameters<typeof startGoogleAnalytics>[1], process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID);
  const key = process.env.NEXT_PUBLIC_POSTHOG_KEY;
  if (!key) return;
  posthog.init(key, {
    api_host: "https://us.i.posthog.com",
    defaults: "2025-05-24", // history-API pageviews + pageleave for the SPA router
    respect_dnt: true,
    autocapture: false, // explicit funnel events only — keeps the data legible
  });
  initialised = true;
}

export function track(event: string, properties?: Record<string, string | number | boolean>): void {
  if (!initialised) return;
  posthog.capture(event, properties);
}
