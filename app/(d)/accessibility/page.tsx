import type { Metadata } from "next";
import Link from "next/link";
import { Reveal } from "@/components/d/bits";
import { LockMark } from "@/components/d/Brand";

// Accessibility statement.
//
// Written to the same standard as everything else here: it describes what has
// actually been done and what has not, rather than asserting compliance. A
// statement claiming conformance we have not measured would be the same category
// of error as a security finding we cannot demonstrate.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Accessibility",
  description:
    "ShipLock's accessibility statement: the standard we build to, what has been verified, what has not, and how to report a barrier.",
};

export default function AccessibilityPage() {
  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/" className="dxd-wordmark">
              <span className="dxd-wordmark-lock"><LockMark size={19} /></span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <Link href="/coverage">Coverage</Link>
              <Link href="/terms">Terms</Link>
              <Link href="/privacy">Privacy</Link>
            </div>
          </nav>

          <header className="dxd-dash-hero">
            <p className="dxd-eyebrow">Accessibility</p>
            <h1 className="dxd-statement">Built to WCAG 2.2 Level AA.</h1>
            <p className="dxd-lede" style={{ margin: "18px 0 0", maxWidth: "62ch" }}>
              This statement describes what has been implemented and verified, and what has
              not. We would rather name an unmeasured area than claim conformance we have
              not tested.
            </p>
          </header>
        </div>
      </div>

      <div className="dxd-shell dxd-dash-body" style={{ maxWidth: "72ch" }}>
        <Reveal>
          <section aria-label="Standard">
            <h2 className="dxd-serif" style={{ fontSize: 20 }}>The standard we target</h2>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)" }}>
              ShipLock targets the Web Content Accessibility Guidelines (WCAG) 2.2 at Level AA.
              That is the benchmark referenced by the Americans with Disabilities Act in US
              enforcement practice, by Section 508 for federal procurement, and by the European
              Accessibility Act. We treat it as the design standard for the product, not as a
              checklist applied afterwards.
            </p>
          </section>
        </Reveal>

        <Reveal>
          <section aria-label="Implemented" style={{ marginTop: 32 }}>
            <h2 className="dxd-serif" style={{ fontSize: 20 }}>What is implemented</h2>
            <ul style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 10 }}>
              {[
                "Semantic structure throughout: landmarks, a single document heading order, and labelled regions on every panel rather than styled div containers.",
                "Full keyboard operation. Every interactive control is reachable and operable without a pointer, and focus is visible against both themes.",
                "Text contrast meeting or exceeding 4.5:1, and non-text contrast of 3:1 for controls and focus indicators.",
                "Status conveyed by more than colour. Severity carries a text label wherever it carries a colour, so the distinction survives greyscale and the common forms of colour blindness.",
                "Reduced-motion support: every animation is behind prefers-reduced-motion, and none of them is required to understand the content.",
                "Content that reflows to 320px without horizontal scrolling, and remains usable at 200% zoom.",
                "Form fields with programmatically associated labels, and errors described in text rather than by colour or position.",
              ].map((line) => (
                <li key={line} style={{ fontSize: 14.5, lineHeight: 1.75, color: "var(--d-muted)" }}>{line}</li>
              ))}
            </ul>
          </section>
        </Reveal>

        <Reveal>
          <section aria-label="Known limitations" style={{ marginTop: 32 }}>
            <h2 className="dxd-serif" style={{ fontSize: 20 }}>Known limitations</h2>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)" }}>
              We have not yet completed an audit with assistive technology across the full range
              of screen readers, so conformance is asserted from implementation and automated
              checking rather than from verified user testing. Some dense finding tables are
              usable but not yet optimal to navigate by screen reader, and code and SQL blocks
              are presented as preformatted text without per-token semantics.
            </p>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)", marginTop: 12 }}>
              Neither is a reason to wait before telling us something is unusable. If a barrier
              stops you completing a task, that takes priority over the roadmap.
            </p>
          </section>
        </Reveal>

        <Reveal>
          <section aria-label="Reporting a barrier" style={{ marginTop: 32 }}>
            <h2 className="dxd-serif" style={{ fontSize: 20 }}>Reporting a barrier</h2>
            <p style={{ fontSize: 14.5, lineHeight: 1.8, color: "var(--d-muted)" }}>
              Write to{" "}
              <a href="mailto:support@shiplock.dev">support@shiplock.dev</a> with the page and
              what you were trying to do. We aim to acknowledge within two business days and to
              give you a workaround in the same reply where one exists. If you need information
              held in your dashboard in a different format, ask and we will provide it.
            </p>
            <p style={{ fontSize: 13.5, lineHeight: 1.8, color: "var(--d-muted-light)", marginTop: 16 }}>
              Last reviewed 30 July 2026. This statement is reviewed whenever the interface
              changes materially.
            </p>
          </section>
        </Reveal>
      </div>
    </main>
  );
}
