// "Floating Lines" — extremely subtle background texture for the hero
// only. Two large, low-opacity strokes drifting a few percent over a
// slow cycle. Intentionally almost invisible — a texture, not a graphic.
export function FloatingLines() {
  return (
    <svg
      className="pointer-events-none absolute inset-0 -z-10 h-full w-full opacity-[0.06]"
      viewBox="0 0 1200 800"
      preserveAspectRatio="xMidYMid slice"
      aria-hidden
    >
      <path
        d="M-100 200 C 300 50, 700 350, 1300 120"
        stroke="var(--accent-indigo)"
        strokeWidth="1.5"
        fill="none"
        style={{ animation: "float-line-a 22s ease-in-out infinite" }}
      />
      <path
        d="M-100 600 C 350 420, 750 720, 1300 480"
        stroke="var(--foreground)"
        strokeWidth="1"
        fill="none"
        style={{ animation: "float-line-b 26s ease-in-out infinite" }}
      />
    </svg>
  );
}
