"use client";

// The dashboard's lock. Real scan output only reports OPEN issues
// (lib/analyzer.ts never reports passing checks), so there is no per-check
// "verified" signal to plot — only a total check count (a stable constant from
// lib/scanner.ts) and however many are currently open. Pins are drawn only for
// open issues.
//
// Rebuilt 2026-07-27 on the hex mark from components/d/Brand.tsx: the body is
// the same hexagon, and a sweep runs its perimeter to show the watch working
// through the surfaces. Six edges, six discrete segments — the sweep reads as
// checking things in sequence rather than spinning decoratively.

import { useId } from "react";
import { LockMark } from "./Brand";

const W = 300;
const CX = 150;
const CY = 222;
const BODY_R = 112;
const TEXT_R = 96;
const PIN_R = 58;

// Pointy-top hexagon on the same proportions as the mark, scaled to BODY_R.
function hexPath(cx: number, cy: number, r: number): string {
  const pts = Array.from({ length: 6 }, (_, k) => {
    const a = ((-90 + 60 * k) * Math.PI) / 180;
    return `${(cx + r * Math.cos(a)).toFixed(1)} ${(cy + r * Math.sin(a)).toFixed(1)}`;
  });
  return `M${pts.join("L")}Z`;
}

export interface LockIssue {
  title: string;
  severity: "CRITICAL" | "WARNING" | "INFO";
}

export function Lock({
  totalChecks,
  issues,
  onSelect,
}: {
  totalChecks: number;
  issues: LockIssue[];
  onSelect?: (index: number) => void;
}) {
  const id = useId();
  const secured = totalChecks - issues.length;
  const locked = issues.length === 0;

  return (
    <div
      className="dxdl"
      data-locked={locked}
      role="group"
      aria-label={`The lock: ${secured} of ${totalChecks} checks secured${locked ? " — locked" : ""}`}
    >
      <svg className="dxdl-svg" viewBox={`0 0 ${W} 360`} aria-hidden="true">
        <defs>
          <path
            id={`${id}-ring`}
            d={`M ${CX},${CY} m -${TEXT_R},0 a ${TEXT_R},${TEXT_R} 0 1,1 ${TEXT_R * 2},0 a ${TEXT_R},${TEXT_R} 0 1,1 -${TEXT_R * 2},0`}
          />
        </defs>

        {/* Shackle geometry is the mark's, scaled — not eyeballed. Mapping
            Brand.tsx's 24-unit space onto this one (scale = BODY_R / 7.2,
            centre (12,15.6) -> (150,222)) puts the legs at x 94/206 with their
            feet at y 141, so they meet the hexagon's upper edges exactly.
            The previous ±42 legs were both too narrow and too high, which read
            as a shackle floating detached above the body. */}
        <g className="dxdl-shackle">
          <path
            d="M 94 141.1 V 91.3 A 56 56 0 0 1 206 91.3 V 141.1"
            fill="none"
            strokeWidth="9"
            strokeLinecap="round"
          />
        </g>

        {/* Hex body, matching the mark. */}
        <path
          className="dxdl-circle"
          d={hexPath(CX, CY, BODY_R)}
          fill="none"
          strokeWidth="1.2"
          strokeLinejoin="round"
        />
        <path
          className="dxdl-circle"
          d={hexPath(CX, CY, BODY_R - 32)}
          fill="none"
          strokeWidth="0.75"
          strokeLinejoin="round"
        />

        {/* The sweep: traces the hex perimeter, one pass per cycle. */}
        <path
          className="dxdl-sweep"
          d={hexPath(CX, CY, BODY_R)}
          fill="none"
          strokeWidth="1.6"
          strokeLinejoin="round"
          stroke="var(--d-bronze-light)"
        />

        <g className="dxdl-ringtext">
          <text fontSize="8.6">
            <textPath href={`#${id}-ring`}>
              CONTINUOUS COVER · SHIPLOCK · EVIDENCE ON FILE · SIXTEEN CHECKS ·
            </textPath>
          </text>
        </g>
      </svg>

      <div className="dxdl-center">
        <span className="dxdl-mark">
          <LockMark size={20} />
        </span>
        <div className="dxdl-count">
          {secured}
          <em>/{totalChecks}</em>
        </div>
        <div className="dxdl-word">{locked ? "Locked" : "Securing"}</div>
      </div>

      {issues.map((issue, i) => {
        const a = (i / Math.max(issues.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const left = CX + PIN_R * Math.cos(a);
        const top = CY + PIN_R * Math.sin(a);
        const interactive = typeof onSelect === "function";
        return (
          <button
            key={`${issue.title}-${i}`}
            type="button"
            className="dxdl-pin"
            data-state="needs"
            style={{ left, top, cursor: interactive ? "pointer" : "default" }}
            onClick={interactive ? () => onSelect(i) : undefined}
            aria-label={
              interactive
                ? `${issue.title}: needs you. Open on the board.`
                : `${issue.title}: needs you.`
            }
          >
            <span className="dxdl-tip" role="presentation">
              {issue.title} · needs you
            </span>
          </button>
        );
      })}
    </div>
  );
}
