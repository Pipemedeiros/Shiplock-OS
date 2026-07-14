import type { Guardrail } from "@/lib/guardrails";
import type { JwtSigningPosture } from "@/lib/security/sessionAudit";

// Presentational, server-safe (no hooks). Renders the copy-paste agent audit
// prompts for the categories no scanner can reach, plus the live JWT-signing
// posture. Static guidance + one externally-checked readout — nothing
// paywall-sensitive.

export function GuardrailPanel({
  guardrails,
  jwtPosture,
}: {
  guardrails: Guardrail[];
  jwtPosture: JwtSigningPosture | null;
}) {
  return (
    <section style={{ marginTop: 40 }} aria-label="Guardrails — what we can't scan for you">
      <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
        Guardrails · the parts no scanner can reach
      </p>
      <p className="dxd-lede" style={{ marginBottom: 16 }}>
        Your database and config we watch continuously. Business logic and your own app code,
        no scanner can — so here are the exact prompts to hand your coding agent to audit them
        yourself. You already have a running app; these find what&apos;s already there.
      </p>

      {jwtPosture && (
        <div
          className="dxd-surface"
          style={{ marginBottom: 20, borderLeft: `3px solid ${jwtPosture.ok ? "var(--d-bronze)" : "var(--d-line)"}` }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12 }}>
            <h3 style={{ margin: 0, fontSize: 15 }}>{jwtPosture.title}</h3>
            <span className={`dxd-chip ${jwtPosture.ok ? "dxd-chip-verified" : "dxd-chip-critical"}`}>
              {jwtPosture.ok ? "checked" : "action"}
            </span>
          </div>
          <p style={{ margin: "10px 0 0", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
            {jwtPosture.detail}
          </p>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 20 }}>
        {guardrails.map((g) => (
          <div key={g.id} className="dxd-surface">
            <h3 style={{ margin: "0 0 8px", fontSize: 15 }}>{g.surface}</h3>
            <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
              {g.why}
            </p>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {g.prompts.map((p, i) => (
                <p
                  key={i}
                  className="dxd-mono"
                  style={{
                    margin: 0,
                    fontSize: 11,
                    lineHeight: 1.6,
                    background: "var(--d-porcelain)",
                    border: "1px solid var(--d-line)",
                    borderRadius: 8,
                    padding: "10px 12px",
                    userSelect: "all",
                  }}
                >
                  {p}
                </p>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
