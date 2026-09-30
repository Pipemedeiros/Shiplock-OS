import type { Metadata } from "next";
import { Newsreader, Geist, Geist_Mono } from "next/font/google";
import "./design-base.css";
import "./design-d.css";
import "./v3.css";
import { CookieConsent } from "@/components/CookieConsent";

// Product layout for /, /auth, /onboarding and /dashboard (a route group, so
// no URL segment). Fonts are self-hosted via next/font so the CSP in proxy.ts
// (font 'self') holds. Only the v3 families: every family listed here is
// preloaded on every page (app/fonts.test.ts).

const newsreader = Newsreader({
  variable: "--dx-font-newsreader",
  subsets: ["latin"],
  style: ["normal", "italic"],
});

const geist = Geist({
  variable: "--dx-font-geist",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--dx-font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL ?? "https://shiplock.dev"),
  title: {
    default: "ShipLock: security monitoring that opens the pull request",
    template: "%s · ShipLock",
  },
  description:
    "Connect GitHub. ShipLock reads your code, finds the paths that reach customer data, and opens the fix as a pull request.",
  openGraph: {
    siteName: "ShipLock",
    type: "website",
    // app/opengraph-image.tsx renders the card; listing it here makes the
    // default explicit for pages that don't override it.
  },
  twitter: {
    card: "summary_large_image",
  },
};

export default function DLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <div
      className={`dx-root ${newsreader.variable} ${geist.variable} ${geistMono.variable}`}
    >
      {children}
      <CookieConsent />
    </div>
  );
}
