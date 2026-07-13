import { ImageResponse } from "next/og";

// Site-wide OG/social card (1200×630) rendered with next/og — no binary
// asset to maintain, and it inherits the Design D palette. Placeholder
// mark: the LockGlyph drawing from components/d/Brand.tsx; when the
// owner's logo lands, swap the <svg> block only.

export const runtime = "edge";
export const alt = "ShipLock — continuous security monitoring for AI-built apps";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          padding: "80px 96px",
          background: "#f7f8fa",
          color: "#122036",
          fontFamily: "Georgia, serif",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
          <svg
            width="72"
            height="72"
            viewBox="0 0 24 24"
            fill="none"
            stroke="#8a6b2f"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M8.2 11V8.4a3.8 3.8 0 0 1 7.6 0V11" />
            <rect x="4.9" y="11" width="14.2" height="9" rx="2.6" />
            <circle cx="12" cy="15.5" r="1.25" fill="#8a6b2f" stroke="none" />
          </svg>
          <div style={{ fontSize: 56, fontWeight: 700, display: "flex" }}>
            ShipLock<span style={{ color: "#8a6b2f" }}>.</span>
          </div>
        </div>
        <div
          style={{
            marginTop: 48,
            fontSize: 64,
            lineHeight: 1.15,
            fontWeight: 700,
            display: "flex",
            flexDirection: "column",
          }}
        >
          <span>You built something worth protecting.</span>
          <span style={{ color: "#8a6b2f", fontStyle: "italic" }}>We carry the worry.</span>
        </div>
        <div
          style={{
            marginTop: 44,
            fontSize: 28,
            color: "#5a6478",
            display: "flex",
          }}
        >
          Continuous security monitoring for AI-built apps · 16 checks · $49/mo
        </div>
      </div>
    ),
    size
  );
}
