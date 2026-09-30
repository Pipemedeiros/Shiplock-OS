import Link from "next/link";
import type { ReactNode } from "react";
import { LockMark } from "@/components/d/Brand";

/** A one-message page in the v3 frame: welcome, cancelled. */
export function StatusPage({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return (
    <div className="v3" style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top" aria-label="ShipLock">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
          </nav>
        </div>
      </div>
      <main className="v3-narrow" style={{ flex: 1, width: "100%", padding: "72px 28px 64px" }}>
        <p className="v3-eyebrow v3-mono">{eyebrow}</p>
        <h1 className="v3-serif" style={{ fontSize: 40, lineHeight: 1.15, margin: "14px 0 14px" }}>{title}</h1>
        {children}
      </main>
    </div>
  );
}
