"use client";

// Direction D signature #2: the Lock — now drawn as the seal, scaled up
// and made live. Gold line-art on the band: a slowly turning ring of
// text, fine concentric circles, the minimal lock mark, and the 15
// checks as quiet dots on an inner ring. The shackle stands open while
// anything needs the owner and clicks shut when the last check
// verifies. Dots are real buttons: hover for the check, click to open
// its row on the board.

import { useId } from "react";
import { CHECKS } from "../_shared/data";
import { LockMark } from "./Brand";

export type PinState = "verified" | "needs" | "fresh";

const W = 300;
const CX = 150;
const CY = 222;
const BODY_R = 112;
const TEXT_R = 96;
const INNER_R = 80;
const PIN_R = 58;

const STATE_TEXT: Record<PinState, string> = {
  verified: "verified",
  needs: "needs you",
  fresh: "verified just now",
};

export function Lock({
  states,
  secured,
  onSelect,
}: {
  states: Record<number, PinState>;
  secured: number;
  onSelect: (checkId: number) => void;
}) {
  const id = useId();
  const locked = secured === CHECKS.length;

  return (
    <div
      className="dxdl"
      data-locked={locked}
      role="group"
      aria-label={`The lock: ${secured} of ${CHECKS.length} checks secured${locked ? " — locked" : ""}`}
    >
      <svg className="dxdl-svg" viewBox={`0 0 ${W} 360`} aria-hidden="true">
        <defs>
          <path
            id={`${id}-ring`}
            d={`M ${CX},${CY} m -${TEXT_R},0 a ${TEXT_R},${TEXT_R} 0 1,1 ${TEXT_R * 2},0 a ${TEXT_R},${TEXT_R} 0 1,1 -${TEXT_R * 2},0`}
          />
        </defs>

        {/* shackle */}
        <g className="dxdl-shackle">
          <path
            d="M 106 118 V 94 A 44 44 0 0 1 194 94 V 118"
            fill="none"
            strokeWidth="9"
            strokeLinecap="round"
          />
        </g>

        {/* seal body: fine concentric circles, no fill */}
        <circle className="dxdl-circle" cx={CX} cy={CY} r={BODY_R} strokeWidth="1" />
        <circle className="dxdl-circle" cx={CX} cy={CY} r={INNER_R} strokeWidth="0.75" />

        {/* the turning ring of text — same register as the seal */}
        <g className="dxdl-ringtext">
          <text fontSize="8.6">
            <textPath href={`#${id}-ring`}>
              CONTINUOUS COVER · SHIPLOCK · EVIDENCE ON FILE · FIFTEEN CHECKS ·
            </textPath>
          </text>
        </g>

        {/* click flash on lock */}
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
          <em>/{CHECKS.length}</em>
        </div>
        <div className="dxdl-word">{locked ? "Locked" : "Securing"}</div>
      </div>

      {CHECKS.map((c, i) => {
        const a = (i / CHECKS.length) * Math.PI * 2 - Math.PI / 2;
        const left = CX + PIN_R * Math.cos(a);
        const top = CY + PIN_R * Math.sin(a);
        const state = states[c.id] ?? "verified";
        return (
          <button
            key={c.id}
            type="button"
            className="dxdl-pin"
            data-state={state}
            style={{ left, top }}
            onClick={() => onSelect(c.id)}
            aria-label={`Check ${c.id}, ${c.name}: ${STATE_TEXT[state]}. Open on the board.`}
          >
            <span className="dxdl-tip" role="presentation">
              {c.name} · {STATE_TEXT[state]}
            </span>
          </button>
        );
      })}
    </div>
  );
}
