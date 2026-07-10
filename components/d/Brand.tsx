// The mark: the most reduced padlock that still reads instantly —
// one shackle arc, one softly-squared body, one dot. Nothing else.
// Always bronze, always this exact drawing, at every size.

export function LockGlyph() {
  // drawn in a 24×24 space; stroke/color come from the parent
  return (
    <>
      <path d="M8.2 11V8.4a3.8 3.8 0 0 1 7.6 0V11" />
      <rect x="4.9" y="11" width="14.2" height="9" rx="2.6" />
      <circle cx="12" cy="15.5" r="1.25" fill="currentColor" stroke="none" />
    </>
  );
}

export function LockMark({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <LockGlyph />
    </svg>
  );
}
