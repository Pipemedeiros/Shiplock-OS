import { ImageResponse } from "next/og";

// Site-wide OG/social card (1200×630) rendered with next/og — no binary
// asset to maintain, and it inherits the Design D palette. Placeholder
// mark: the LockGlyph drawing from components/d/Brand.tsx; when the
// owner's logo lands, swap the <svg> block only.

export const runtime = "edge";
export const alt = "ShipLock — continuous security monitoring for apps in production";
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
            strokeWidth="1.1"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M8.4 10.4V7.2a3.6 3.6 0 0 1 7.2 0v3.2" />
            <path d="M12 8.4 18.4 12.1v7L12 22.8l-6.4-3.7v-7L12 8.4Z" />
            <circle cx="12" cy="14.6" r="1.2" />
            <path d="M12 15.8v2" />
            <path d="M5.6 16.3 13.6 20.9" opacity="0.9" />
            <path d="M5.6 18.9 10.6 21.8" opacity="0.5" />
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
          <span>One permissive policy exposes every row.</span>
          <span style={{ color: "#8a6b2f", fontStyle: "italic" }}>We find it, fix it, and keep proving it.</span>
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
