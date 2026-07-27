// The mark: a hexagonal lock — arched shackle seated behind a hex body, keyhole
// at centre, and (display sizes only) the diagonal sweep across the lower left.
// Drawn from the owner's reference lockup, in a 24×24 space so every consumer
// keeps the same viewBox.
//
// Three cuts, because one drawing cannot serve 14px and 72px:
//   display (>=40px) — everything, including the sweep, hairline stroke
//   app     (18-39px) — sweep dropped, keyhole open, slightly heavier stroke
//   micro   (<18px)   — keyhole becomes a solid dot, heaviest stroke
// Stroke comes from the parent so the mark inherits bronze in light theme and
// bronze-light in dark with no per-theme fork.

export function LockGlyph() {
  // App cut — the default drawing. Stroke/color come from the parent.
  return (
    <>
      <path d="M8.4 10.4V7.2a3.6 3.6 0 0 1 7.2 0v3.2" />
      <path d="M12 8.4 18.4 12.1v7L12 22.8l-6.4-3.7v-7L12 8.4Z" />
      <circle cx="12" cy="14.6" r="1.2" />
      <path d="M12 15.8v2" />
    </>
  );
}

export function LockGlyphDisplay() {
  // Adds the diagonal sweep from the reference lockup. Only legible >=40px.
  return (
    <>
      <LockGlyph />
      <path d="M5.6 16.3 13.6 20.9" opacity="0.9" />
      <path d="M5.6 18.9 10.6 21.8" opacity="0.5" />
    </>
  );
}

export function LockGlyphMicro() {
  // Keyhole collapses to a filled dot; everything else holds its shape.
  return (
    <>
      <path d="M8.4 10.4V7.2a3.6 3.6 0 0 1 7.2 0v3.2" />
      <path d="M12 8.4 18.4 12.1v7L12 22.8l-6.4-3.7v-7L12 8.4Z" />
      <circle cx="12" cy="15.4" r="1.35" fill="currentColor" stroke="none" />
    </>
  );
}

export function LockMark({ size = 20 }: { size?: number }) {
  const cut = size >= 40 ? "display" : size < 18 ? "micro" : "app";
  const strokeWidth = cut === "display" ? 1.1 : cut === "micro" ? 1.9 : 1.35;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {cut === "display" ? <LockGlyphDisplay /> : cut === "micro" ? <LockGlyphMicro /> : <LockGlyph />}
    </svg>
  );
}
