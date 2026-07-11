"use client";

// Real-data fork of app/design/d/Lock.tsx. The mock version hard-imports a
// fixed 15-item CHECKS taxonomy and draws one pin per check, each
// individually verified/needs/fresh. Real scan output only reports OPEN
// issues (lib/analyzer.ts never reports passing checks), so there is no
// per-check "verified" signal to plot — only a total check count (a real,
// stable constant from lib/scanner.ts) and however many are currently open.
// Pins are drawn only for open issues; the "fresh" (just re-verified) state
// is dropped entirely — there's no real live-re-scan signal for it yet.

import { useId } from "react";
import { LockMark } from "./Brand";

const W = 300;
const CX = 150;
const CY = 222;
const BODY_R = 112;
const TEXT_R = 96;
const INNER_R = 80;
const PIN_R = 58;

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
  onSelect: (index: number) => void;
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

        <g className="dxdl-shackle">
          <path
            d="M 106 118 V 94 A 44 44 0 0 1 194 94 V 118"
            fill="none"
            strokeWidth="9"
            strokeLinecap="round"
          />
        </g>

        <circle className="dxdl-circle" cx={CX} cy={CY} r={BODY_R} strokeWidth="1" />
        <circle className="dxdl-circle" cx={CX} cy={CY} r={INNER_R} strokeWidth="0.75" />

        <g className="dxdl-ringtext">
          <text fontSize="8.6">
            <textPath href={`#${id}-ring`}>
              CONTINUOUS COVER · SHIPLOCK · EVIDENCE ON FILE · SIXTEEN CHECKS ·
            </textPath>
          </text>
        </g>

        <circle
          className="dxdl-flash"
          cx={CX}
          cy={CY}
          r={BODY_R}
          fill="none"
          stroke="var(--d-bronze-light)"
        />
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
        return (
          <button
            key={`${issue.title}-${i}`}
            type="button"
            className="dxdl-pin"
            data-state="needs"
            style={{ left, top }}
            onClick={() => onSelect(i)}
            aria-label={`${issue.title}: needs you. Open on the board.`}
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
