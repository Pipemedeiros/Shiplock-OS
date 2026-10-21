import type { Metadata } from "next";
import Link from "next/link";
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

const IMPLEMENTED = [
  "Semantic structure throughout: landmarks, a single document heading order, and labelled regions on every panel rather than styled div containers.",
  "Full keyboard operation. Every interactive control is reachable and operable without a pointer, and focus is visible on both the light and the navy surfaces.",
  "Text contrast meeting or exceeding 4.5:1, and non-text contrast of 3:1 for controls and focus indicators.",
  "Status conveyed by more than colour. Severity carries a text label wherever it carries a colour, so the distinction survives greyscale and the common forms of colour blindness.",
  "Reduced-motion support: every animation is behind prefers-reduced-motion, and none of them is required to understand the content.",
  "Content that reflows to 320px without horizontal scrolling, and remains usable at 200% zoom.",
  "Form fields with programmatically associated labels, and errors described in text rather than by colour or position.",
];

export default function AccessibilityPage() {
  return (
    <main className="v3">
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top" aria-label="Main">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
            <div className="v3-nav-links">
              <Link className="v3-nav-secondary" href="/coverage">Coverage</Link>
              <Link href="/terms">Terms</Link>
              <Link href="/privacy">Privacy</Link>
            </div>
          </nav>

          <header className="v3-hero">
            <p className="v3-vr-kicker">Accessibility</p>
            <h1 className="v3-serif">Built to WCAG 2.2 Level AA.</h1>
            <p>
              This statement describes what has been implemented and verified, and what has
              not. We would rather name an unmeasured area than claim conformance we have
              not tested.
            </p>
          </header>
        </div>
      </div>

      <div className="v3-shell v3-scope v3-a11y">
        <section aria-labelledby="a11y-standard">
          <h2 id="a11y-standard" className="v3-serif">The standard we target</h2>
          <p>
            ShipLock targets the Web Content Accessibility Guidelines (WCAG) 2.2 at Level AA.
            That is the benchmark referenced by the Americans with Disabilities Act in US
            enforcement practice, by Section 508 for federal procurement, and by the European
            Accessibility Act. We treat it as the design standard for the product, not as a
            checklist applied afterwards.
          </p>
        </section>

        <section aria-labelledby="a11y-implemented">
          <h2 id="a11y-implemented" className="v3-serif">What is implemented</h2>
          <ul className="v3-scope-detail">
            {IMPLEMENTED.map((line) => <li key={line}>{line}</li>)}
          </ul>
        </section>

        <section aria-labelledby="a11y-limits">
          <h2 id="a11y-limits" className="v3-serif">Known limitations</h2>
          <p>
            We have not yet completed an audit with assistive technology across the full range
            of screen readers, so conformance is asserted from implementation and automated
            checking rather than from verified user testing. Some dense finding tables are
            usable but not yet optimal to navigate by screen reader, and code and SQL blocks
            are presented as preformatted text without per-token semantics.
          </p>
          <p>
            Neither is a reason to wait before telling us something is unusable. If a barrier
            stops you completing a task, that takes priority over the roadmap.
          </p>
        </section>

        <section aria-labelledby="a11y-report">
          <h2 id="a11y-report" className="v3-serif">Reporting a barrier</h2>
          <p>
            Write to{" "}
            <a href="mailto:support@shiplock.dev" className="v3-vr-link">support@shiplock.dev</a> with the page and
            what you were trying to do. We aim to acknowledge within two business days and to
            give you a workaround in the same reply where one exists. If you need information
            held in your dashboard in a different format, ask and we will provide it.
          </p>
          <p className="v3-small">
            Last reviewed 20 October 2026. This statement is reviewed whenever the interface
            changes materially.
          </p>
        </section>
      </div>
    </main>
  );
}
