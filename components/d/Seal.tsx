"use client";

// Direction D: the coverage seal. A quiet, slowly turning mark — bronze
// while every claim on the board is verified, muted while something
// needs the owner. Decorative authority, never the only signal.

import { useId } from "react";
import { LockGlyph } from "./Brand";

export function Seal({
  state,
  size = 132,
}: {
  state: "intact" | "attention";
  size?: number;
}) {
  const id = useId();
  const ring = state === "intact" ? "#8a6b2f" : "#9fb0c4";
  return (
    <svg
      className="dxd-seal"
      width={size}
      height={size}
      viewBox="0 0 120 120"
      role="img"
      aria-label={
        state === "intact"
          ? "Coverage seal: all checks verified"
          : "Coverage seal: attention required"
      }
    >
      <defs>
        <path
          id={`${id}-c`}
          d="M 60,60 m -44,0 a 44,44 0 1,1 88,0 a 44,44 0 1,1 -88,0"
        />
      </defs>
      <circle cx="60" cy="60" r="55" fill="none" stroke={ring} strokeWidth="1" opacity="0.5" />
      <circle cx="60" cy="60" r="33" fill="none" stroke={ring} strokeWidth="1" opacity="0.7" />
      <g className="dxd-seal-ring">
        <text fontSize="8.4" fill={ring}>
          <textPath href={`#${id}-c`}>
            CONTINUOUS COVER · SHIPLOCK · EVIDENCE ON FILE ·
          </textPath>
        </text>
      </g>
      <g
        transform="translate(46.2 40.2) scale(1.15)"
        fill="none"
        stroke={ring}
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        style={{ color: ring }}
      >
        <LockGlyph />
      </g>
      <text
        x="60"
        y="82"
        textAnchor="middle"
        fontSize="6.4"
        letterSpacing="0.18em"
        fill={ring}
      >
        {state === "intact" ? "VERIFIED" : "ATTENTION"}
      </text>
    </svg>
  );
}
