import type { CSSProperties } from "react";

// Pure-CSS live-traffic visualization for the landing page. No client JS.
// ACCURATE to lib/traffic/*: detection is OUT-OF-BAND, not an inline WAF. A
// coordinated ~13s loop tells the true story — login attempts stream in and
// PASS THROUGH while ShipLock mirrors and analyzes them; once the
// credential-stuffing pattern is recognized, the edge locks and that source's
// NEXT attempts are turned away with a 429. Legitimate traffic flows the whole
// time. Decorative — role="img" carries the meaning; parts are aria-hidden.

const LEGIT = [
  { lane: 0, label: "GET /", dur: "5.6s", delay: "0.4s" },
  { lane: 4, label: "POST /api/orders", dur: "6.4s", delay: "2.6s" },
  { lane: 5, label: "GET /pricing", dur: "5.9s", delay: "4.1s" },
];

// Same source (a credential-stuffing bot) — these pass, then get mirrored.
const SUSPECT = [
  { lane: 2, delay: "0s" },
  { lane: 2, delay: "1.3s" },
  { lane: 2, delay: "2.6s" },
];

// The same source after detection — now blocked at the edge.
const REPEL = [
  { lane: 2, delay: "0s" },
  { lane: 3, delay: "0.7s" },
];

const v = (o: Record<string, string | number>) => o as CSSProperties;

export function TrafficDefense() {
  return (
    <div
      className="dxd-td"
      role="img"
      aria-label="Login attempts stream in from the left and pass through to your app while ShipLock mirrors and analyzes them. Once the burst is recognized as credential stuffing, the source is blocked, and its next attempts are turned away at ShipLock's edge with a 429. Legitimate traffic keeps flowing the entire time."
    >
      <div className="dxd-td-grid" aria-hidden="true" />
      <span className="dxd-td-tag in" aria-hidden="true">inbound</span>
      <span className="dxd-td-tag out" aria-hidden="true">served</span>
      <span className="dxd-td-edge-label" aria-hidden="true">ShipLock edge</span>
      <div className="dxd-td-edge" aria-hidden="true" />
      <div className="dxd-td-app" aria-hidden="true">your app</div>
      <span className="dxd-td-alert" aria-hidden="true">⚠ credential stuffing — source blocked</span>

      {LEGIT.map((p, i) => (
        <span
          key={`l${i}`}
          className="dxd-td-pkt dxd-td-pass"
          aria-hidden="true"
          style={v({ "--lane": p.lane, "--dur": p.dur, "--delay": p.delay })}
        >
          {p.label}
        </span>
      ))}

      {SUSPECT.map((p, i) => (
        <span
          key={`s${i}`}
          className="dxd-td-pkt dxd-td-suspect"
          aria-hidden="true"
          style={v({ "--lane": p.lane, "--delay": p.delay })}
        >
          POST /login
        </span>
      ))}

      {REPEL.map((p, i) => (
        <span
          key={`r${i}`}
          className="dxd-td-pkt dxd-td-repel"
          aria-hidden="true"
          style={v({ "--lane": p.lane, "--delay": p.delay })}
        >
          POST /login
        </span>
      ))}

      <div className="dxd-td-tap" aria-hidden="true" />
      <span className="dxd-td-mirror" aria-hidden="true">mirror → analyze</span>
    </div>
  );
}
