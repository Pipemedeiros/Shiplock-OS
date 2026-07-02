// "Logo Loop" — horizontal looping row of source-platform marks. All
// marks are drawn inline (no external image hosts), monochrome/muted so
// the row reads as a texture, not a badge wall.
function Mark({ label, path, viewBox = "0 0 24 24" }: { label: string; path: string; viewBox?: string }) {
  return (
    <span className="flex shrink-0 items-center gap-2.5 px-8">
      <svg viewBox={viewBox} className="size-5 shrink-0 fill-current text-foreground/35" aria-hidden>
        <path d={path} />
      </svg>
      <span className="text-sm font-medium text-foreground/35">{label}</span>
    </span>
  );
}

const MARKS = [
  {
    label: "GitHub",
    path: "M12 2C6.48 2 2 6.58 2 12.2c0 4.5 2.87 8.31 6.84 9.66.5.1.68-.22.68-.5 0-.24-.01-1.04-.01-1.88-2.78.62-3.37-1.24-3.37-1.24-.45-1.18-1.11-1.5-1.11-1.5-.9-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05a9.29 9.29 0 0 1 5 0c1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.79-4.57 5.05.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.6.69.5A9.96 9.96 0 0 0 22 12.2C22 6.58 17.52 2 12 2Z",
  },
  { label: "Vercel", path: "M12 3 L22 21 H2 Z" },
  {
    label: "Supabase",
    path: "M13.6 2.1c.5-.6 1.5-.2 1.5.6v9.1h6.1c.9 0 1.4 1.1.8 1.8L11.9 21.9c-.5.6-1.5.2-1.5-.6v-9.1H4.3c-.9 0-1.4-1.1-.8-1.8L13.6 2.1Z",
  },
  {
    label: "Firebase",
    path: "M4.5 20 6.9 3.7c.1-.8 1.2-1 1.6-.3l2.2 4-1.6 1.9L4.5 20Zm0 0 8.3-6.6 3 5.7c-2 1.4-7.6 2.7-11.3.9Zm14.2-3.9-2.8-13c-.2-.8-1.2-1-1.7-.3L11.4 5.6l6.2 12L21.4 20c.7-.4 1-1.2.7-1.9l-3.4-14Z",
  },
];

export function LogoLoop() {
  const row = [...MARKS, ...MARKS];
  return (
    <div className="relative overflow-hidden py-2" style={{ maskImage: "linear-gradient(90deg, transparent, black 10%, black 90%, transparent)" }}>
      <div className="logo-loop-track flex w-max items-center">
        {row.map((m, i) => (
          <Mark key={`${m.label}-${i}`} {...m} />
        ))}
      </div>
    </div>
  );
}
