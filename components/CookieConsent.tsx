"use client";

import { useEffect, useSyncExternalStore } from "react";
import { initAnalytics } from "@/lib/analytics";

/**
 * Analytics cookies only with the visitor's choice (Felipe, 2026-09-29).
 *
 * PostHog (product analytics) starts only after "accepted". Until a choice is
 * made nothing is initialised; "rejected" is remembered and never asked again.
 * Sign-in cookies are strictly necessary and are not covered by this choice.
 * Mounted once in app/(d)/layout.tsx; replaces the unconditional PostHogInit.
 */
export type Consent = "accepted" | "rejected";
const KEY = "shiplock_consent";
type Store = { getItem(key: string): string | null; setItem(key: string, value: string): void };

export function readConsent(store: Store): Consent | null {
  try {
    const value = store.getItem(KEY);
    return value === "accepted" || value === "rejected" ? value : null;
  } catch {
    return null;
  }
}

export function writeConsent(store: Store, consent: Consent): void {
  try { store.setItem(KEY, consent); } catch { /* storage blocked: the choice lasts this visit */ }
}

export function ConsentBannerView({ onAccept, onReject }: { onAccept: () => void; onReject: () => void }) {
  const button = {
    font: "inherit", fontSize: 13.5, borderRadius: 5, padding: "9px 16px", cursor: "pointer",
    border: "1px solid #2a3b52", background: "transparent", color: "#eef2f7",
  } as const;
  return (
    <div
      role="region"
      aria-label="Cookie choice"
      style={{
        position: "fixed", left: 16, right: 16, bottom: 16, zIndex: 50, margin: "0 auto", maxWidth: 640,
        background: "#0f1b2d", color: "#eef2f7", border: "1px solid #2a3b52", borderRadius: 6,
        padding: "16px 18px", display: "flex", flexWrap: "wrap", gap: 14, alignItems: "center",
        fontFamily: "var(--dx-font-geist), ui-sans-serif, system-ui, sans-serif", fontSize: 14, lineHeight: 1.5,
        boxSizing: "border-box",
      }}
    >
      <p style={{ margin: 0, flex: "1 1 300px", color: "#c7d2df" }}>
        We use analytics cookies to see how ShipLock is used. Sign-in cookies are always on.{" "}
        <a href="/privacy" style={{ color: "#c9a961" }}>Privacy</a>
      </p>
      <div style={{ display: "flex", gap: 8 }}>
        <button type="button" onClick={onReject} style={button}>Reject</button>
        <button type="button" onClick={onAccept} style={button}>Accept</button>
      </div>
    </div>
  );
}

// Browser storage as an external store: the server snapshot is "unknown" so
// nothing renders before hydration, and a choice made here notifies the view.
const listeners = new Set<() => void>();
const subscribe = (listener: () => void) => { listeners.add(listener); return () => listeners.delete(listener); };
let visitChoice: Consent | null = null; // holds the choice when storage is blocked
const snapshot = (): Consent | null => readConsent(window.localStorage) ?? visitChoice;
const serverSnapshot = (): "unknown" => "unknown";

function choose(consent: Consent): void {
  visitChoice = consent;
  writeConsent(window.localStorage, consent);
  if (consent === "accepted") initAnalytics();
  listeners.forEach((listener) => listener());
}

export function CookieConsent() {
  const consent = useSyncExternalStore<Consent | null | "unknown">(subscribe, snapshot, serverSnapshot);

  useEffect(() => {
    if (consent === "accepted") initAnalytics();
  }, [consent]);

  if (consent !== null) return null;
  return <ConsentBannerView onAccept={() => choose("accepted")} onReject={() => choose("rejected")} />;
}
