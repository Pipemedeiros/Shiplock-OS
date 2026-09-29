import Link from "next/link";
import type { Metadata } from "next";
import { Geist, Geist_Mono, Newsreader } from "next/font/google";
import { LockMark } from "@/components/d/Brand";
import "./(d)/v3.css";

/**
 * The 404 for any unmatched URL.
 *
 * It renders in the root layout, outside the (d) route group, so it loads the
 * three fonts and the v3 stylesheet the live pages use itself. A visitor who
 * mistypes an address still lands inside the real product frame: the same
 * header, the same type, the same bronze action.
 *
 * It says what happened and what did not (nothing about their account), then
 * offers the ways back in the order a founder is likely to need them. No
 * apology, no illustration, no search box that would search nothing.
 */
const geist = Geist({ variable: "--dx-font-geist", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--dx-font-geist-mono", subsets: ["latin"] });
const newsreader = Newsreader({ variable: "--dx-font-newsreader", subsets: ["latin"], style: ["normal", "italic"] });

export const metadata: Metadata = {
  title: "Page not found",
  robots: { index: false, follow: false },
};

const WAYS_BACK = [
  { href: "/onboarding", title: "Start with GitHub", body: "Install the GitHub App and choose a repository to audit." },
  { href: "/coverage", title: "What ShipLock covers", body: "The stacks, providers and checks we read today, and what we do not." },
  { href: "/auth", title: "Sign in", body: "Return to your account and your latest audit." },
];

export default function NotFound() {
  return (
    <div className={`${geist.variable} ${geistMono.variable} ${newsreader.variable}`}>
      <div className="v3" style={{ display: "flex", flexDirection: "column" }}>
        <div className="v3-band">
          <div className="v3-shell">
            <nav className="v3-nav-top" aria-label="ShipLock">
              <Link href="/" className="v3-mark">
                <LockMark size={20} /> ShipLock
              </Link>
              <div className="v3-nav-links">
                <Link href="/auth">Sign in</Link>
                <Link href="/onboarding" className="v3-btn v3-btn-sm v3-ondark">Get started</Link>
              </div>
            </nav>
          </div>
        </div>

        <main className="v3-narrow" style={{ flex: 1, width: "100%", padding: "72px 28px 64px" }}>
          <p className="v3-eyebrow v3-mono">404 · Page not found</p>
          <h1 className="v3-serif" style={{ fontSize: 40, lineHeight: 1.15, margin: "14px 0 14px" }}>
            This page does not exist.
          </h1>
          <p className="v3-sub" style={{ fontSize: 16.5, maxWidth: 560 }}>
            The address may be mistyped, or the page may have moved. Nothing about your account, your
            repositories or your findings changed.
          </p>

          <div className="v3-row" style={{ gap: 12, marginTop: 28 }}>
            <Link href="/dashboard" className="v3-btn v3-primary">Open your dashboard</Link>
            <Link href="/" className="v3-btn">Go to the home page</Link>
          </div>

          <section aria-labelledby="ways-back" style={{ marginTop: 56 }}>
            <h2 id="ways-back" className="v3-small v3-mono" style={{ textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
              Or go straight to
            </h2>
            <ul style={{ listStyle: "none", padding: 0, display: "grid", gap: 10 }}>
              {WAYS_BACK.map((way) => (
                <li key={way.href}>
                  <Link href={way.href} className="v3-card" style={{ display: "block", padding: "14px 18px" }}>
                    <span style={{ fontWeight: 500 }}>{way.title}</span>
                    <span className="v3-small" style={{ display: "block", marginTop: 2 }}>{way.body}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </section>
        </main>

        <footer className="v3-shell" style={{ width: "100%", padding: "24px 28px 32px" }}>
          <div className="v3-between v3-small" style={{ borderTop: "1px solid var(--line)", paddingTop: 18 }}>
            <span>ShipLock</span>
            <span className="v3-row" style={{ gap: 18 }}>
              <Link href="/terms">Terms</Link>
              <Link href="/privacy">Privacy</Link>
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
