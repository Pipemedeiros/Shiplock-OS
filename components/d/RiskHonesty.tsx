// Pure-CSS honesty visual for the landing #honest section. A risk scale that
// fills from "exposed" toward "hard target" and stops at 85% — the far end is
// hatched and struck through. The whole point is candor: we reduce risk
// sharply; we never sell 100% invincibility, because it doesn't exist.
export function RiskHonesty() {
  return (
    <div
      className="dxd-risk"
      role="img"
      aria-label="A risk scale from exposed to hard target. ShipLock moves you most of the way toward hardened — a hard target most attackers give up on — but never to 100% unhackable, because that state does not exist."
    >
      <div className="dxd-risk-scale" aria-hidden="true">
        <span>Exposed</span>
        <span className="right">100% unhackable</span>
      </div>
      <div className="dxd-risk-track" aria-hidden="true">
        <div className="dxd-risk-fill" />
        <div className="dxd-risk-void" />
        <div className="dxd-risk-marker" />
      </div>
      <p className="dxd-risk-note">
        We move you to a hard target — the app that isn&apos;t worth an attacker&apos;s
        effort. Not to the far end. Nobody lives there, and anyone who says they can take you
        there is selling you something.
      </p>
    </div>
  );
}
