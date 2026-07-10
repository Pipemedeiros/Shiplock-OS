import type { Metadata } from "next";
import {
  Hanken_Grotesk,
  Fragment_Mono,
  Chakra_Petch,
  JetBrains_Mono,
  Bricolage_Grotesque,
  Figtree,
  Newsreader,
  Geist,
  Geist_Mono,
} from "next/font/google";
import "./design-base.css";
import "./design-d.css";

// Real-product layout for the D-skinned routes (/, /auth, /onboarding,
// /dashboard) — a route group, so it contributes no URL segment. Fonts are
// self-hosted via next/font so middleware.ts's CSP (style/font 'self')
// holds without any changes there. Scoped to this group only so /auth and
// /dashboard-preview outside it keep the root layout's Fraunces/Inter/Plex
// Mono set untouched.

const hanken = Hanken_Grotesk({
  variable: "--dx-font-hanken",
  subsets: ["latin"],
});

const fragmentMono = Fragment_Mono({
  variable: "--dx-font-fragment",
  subsets: ["latin"],
  weight: "400",
});

const chakra = Chakra_Petch({
  variable: "--dx-font-chakra",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const jetbrains = JetBrains_Mono({
  variable: "--dx-font-jetbrains",
  subsets: ["latin"],
});

const bricolage = Bricolage_Grotesque({
  variable: "--dx-font-bricolage",
  subsets: ["latin"],
});

const figtree = Figtree({
  variable: "--dx-font-figtree",
  subsets: ["latin"],
});

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
  title: "ShipLock — Continuous application security",
  description:
    "Enterprise-grade security audits, running every day instead of once a year.",
};

export default function DLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <div
      className={`dx-root ${hanken.variable} ${fragmentMono.variable} ${chakra.variable} ${jetbrains.variable} ${bricolage.variable} ${figtree.variable} ${newsreader.variable} ${geist.variable} ${geistMono.variable}`}
    >
      {children}
    </div>
  );
}
