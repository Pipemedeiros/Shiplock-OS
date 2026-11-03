import Link from "next/link";
import type { ReactNode } from "react";
import { LockMark } from "@/components/d/Brand";

/** A long-form legal page in the v3 frame. */
export function LegalPage({ title, updated, other, children }: {
  title: string; updated: string; other: { href: string; label: string }; children: ReactNode;
}) {
  return (
    <div className="v3" style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top" aria-label="ShipLock">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
            <div className="v3-nav-links">
              <Link href={other.href}>{other.label}</Link>
              <Link href="/auth">Sign in</Link>
            </div>
          </nav>
        </div>
      </div>
      <main className="v3-narrow v3-legal" style={{ flex: 1, width: "100%", padding: "64px 28px" }}>
        <p className="v3-eyebrow v3-mono">Legal</p>
        <h1 className="v3-serif" style={{ fontSize: 40, lineHeight: 1.15, margin: "14px 0 6px" }}>{title}</h1>
        <p className="v3-small">Last updated {updated}.</p>
        {children}
      </main>
      <footer className="v3-shell v3-small" style={{ padding: "24px 28px 40px", display: "flex", gap: 16 }}>
        <Link href="/">Home</Link><Link href={other.href}>{other.label}</Link>
        <a href="mailto:support@shiplock.dev">support@shiplock.dev</a>
      </footer>
    </div>
  );
}
