import type { Metadata } from "next";
import { connection } from "next/server";
import "./globals.css";

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
      className="h-full antialiased"
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
