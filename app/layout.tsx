import type { Metadata } from "next";
import { connection } from "next/server";
import { Fraunces, Inter, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

// Only app/error.tsx and the shadcn primitives still use these; the product
// pages use the v3 fonts from app/(d)/layout.tsx, so none is preloaded.
const fraunces = Fraunces({
  variable: "--font-fraunces",
  subsets: ["latin"],
  preload: false,
  weight: ["600", "700"],
  style: ["normal", "italic"],
});

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  preload: false,
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  preload: false,
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  metadataBase: new URL("https://shiplock.dev"),
  title: "ShipLock: security monitoring that opens the pull request",
  description:
    "Connect GitHub. ShipLock infers your stack, follows the paths to customer data, and opens reviewable fixes while showing exactly what it could not verify.",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // proxy.ts sets a per-request CSP nonce; Next adds it to scripts only when
  // the page renders per request. A prerendered page's scripts are blocked.
  await connection();
  return (
    <html
      lang="en"
      className={`${fraunces.variable} ${inter.variable} ${plexMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
