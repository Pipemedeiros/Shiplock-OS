import { FixCard } from "./FixCard";
import type { FixableFinding } from "@/lib/fixes/lane";

// Unified "fix everything" surface: one editable, buttoned fix per open finding.
// No-hooks wrapper (FixCard owns interactivity). Findings are pre-assembled by
// the dashboard from scan + deep sources. Empty → render nothing.
export function FixesPanel({ findings, projectRef }: { findings: FixableFinding[]; projectRef?: string | null }) {
  if (findings.length === 0) return null;

  return (
    <section className="dxd-surface" aria-label="Fixes">
      <h3 style={{ margin: "0 0 6px", fontSize: 15 }}>Fixes</h3>
      <p style={{ margin: "0 0 14px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        Each fix has a button. Database and RLS changes open a <strong>migration PR</strong> you review and
        merge — your own deploy applies it, we never touch your database directly. Code issues open a fix PR;
        a couple of settings link straight into Supabase. Edit any fix before you open it.
      </p>
      <div style={{ display: "grid", gap: 12 }}>
        {findings.map((f) => (
          <FixCard key={f.id} finding={f} projectRef={projectRef} />
        ))}
      </div>
    </section>
  );
}
