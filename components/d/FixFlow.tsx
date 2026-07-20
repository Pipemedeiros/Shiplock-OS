// Presentational, server-safe (CSS-only animation — no hooks). Illustrates the
// fix pipeline: a finding becomes an exact fix becomes a reviewable PR you merge.
// The hands-off loop, shown not told. Under prefers-reduced-motion the same three
// stages render statically (the CSS disables the cycling). Restrained/editorial,
// consistent with TrafficDefense / RiskHonesty.
export function FixFlow() {
  return (
    <div className="dxd-ff" role="img" aria-label="A finding becomes an exact fix, then a reviewable pull request you merge.">
      <div className="dxd-ff-stage dxd-ff-1">
        <span className="dxd-ff-cap">Found</span>
        <div className="dxd-ff-body">
          <span className="dxd-chip dxd-chip-critical">CRITICAL</span>
          <span className="dxd-ff-mono">invoices — no row-level security</span>
        </div>
      </div>

      <span className="dxd-ff-link dxd-ff-link-1" aria-hidden="true" />

      <div className="dxd-ff-stage dxd-ff-2">
        <span className="dxd-ff-cap">Fixed</span>
        <div className="dxd-ff-body dxd-ff-code">
          <span>ALTER TABLE invoices</span>
          <span>ENABLE ROW LEVEL SECURITY;</span>
          <span>CREATE POLICY owner_only …</span>
        </div>
      </div>

      <span className="dxd-ff-link dxd-ff-link-2" aria-hidden="true" />

      <div className="dxd-ff-stage dxd-ff-3">
        <span className="dxd-ff-cap">Merged by you</span>
        <div className="dxd-ff-body">
          <span className="dxd-chip dxd-chip-verified">✓ PR #128</span>
          <span className="dxd-ff-mono">reviewed &amp; merged — never a silent change</span>
        </div>
      </div>
    </div>
  );
}
