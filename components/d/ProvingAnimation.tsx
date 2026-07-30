// The sandboxed exploitation sequence, shown rather than asserted.
//
// Server-safe and CSS-only — no hooks, no client bundle. The whole animation is
// behind prefers-reduced-motion, and the stages read correctly as a static
// diagram when it is disabled, because the sequence is the content and motion is
// only pacing.
//
// It shows the ordering that makes the claim defensible: the arena is built and
// torn down around the attack, and the fix is proven inside it before anything
// is offered. A visual that showed us attacking "your database" would be
// describing a product we deliberately did not build.

const STAGES = [
  { id: "arena", label: "Arena", body: "Schema and policies rebuilt in isolation. No data copied." },
  { id: "seed", label: "Tenants", body: "Two synthetic accounts seeded. Neither is a real user." },
  { id: "attack", label: "Attack", body: "Signed in as one, we read for the other's rows." },
  { id: "fix", label: "Fix", body: "Candidate applied. Attack re-run, access re-run." },
  { id: "teardown", label: "Teardown", body: "Arena destroyed. Evidence kept." },
] as const;

export function ProvingAnimation() {
  return (
    <div className="dxd-proving" role="img" aria-label="Sequence: an isolated arena is built, seeded with two synthetic tenants, attacked, used to verify a fix, then destroyed.">
      <div className="dxd-proving-track" aria-hidden="true">
        {STAGES.map((stage, i) => (
          <div key={stage.id} className="dxd-proving-stage" style={{ ["--i" as string]: i }}>
            <span className="dxd-proving-dot" />
            <span className="dxd-proving-label dxd-mono">{stage.label}</span>
            <span className="dxd-proving-body">{stage.body}</span>
          </div>
        ))}
        <span className="dxd-proving-sweep" />
      </div>
    </div>
  );
}
