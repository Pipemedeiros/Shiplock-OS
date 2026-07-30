import { formatMoney, SOURCES, type ExposureSummary } from "@/lib/exposure/model";

// The exposure screen (PRODUCT-DESIGN.md §13.5).
//
// The most useful thing on the dashboard at the buying moment, and the most
// dangerous if presented carelessly — LEGAL-MEMO §2 flags negligent
// misrepresentation as our highest exposure, and a dollar figure is exactly
// where that bites.
//
// §13.5 guardrail 5 says the presentation IS part of the safety of this feature,
// so it is enforced here and not left to whoever edits the copy next:
//   · no red, no pulsing, no countdown, no "act now" — the number is frightening
//     enough stated calmly, and dressing it up converts a credible tool into a
//     scare screen and forfeits the honesty position
//   · the arithmetic is shown next to the number, always
//   · every figure carries its source and year, inline
//   · the caveat renders WITH the number, never in a footnote it can be
//     separated from
//   · tables we could not count are named, so the total never reads as complete

export function ExposurePanel({ summary }: { summary: ExposureSummary | null }) {
  // Nothing measured means nothing shown. A zero here would be a claim.
  if (!summary || summary.estimates.length === 0) return null;

  const { estimates, totalRecords, totalEstimate, uncountedTables, regulatoryNote } = summary;

  return (
    <section style={{ marginTop: 40 }} aria-label="Exposure estimate">
      <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
        What a breach would cost
      </p>

      <div className="dxd-surface" style={{ padding: 18 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
          <span className="dxd-serif" style={{ fontSize: 30, lineHeight: 1.1 }}>
            {formatMoney(totalEstimate)}
          </span>
          <span style={{ fontSize: 13.5, color: "var(--d-muted)" }}>
            across {totalRecords.toLocaleString()} records holding personal data
          </span>
        </div>

        <p style={{ margin: "14px 0 0", fontSize: 13, lineHeight: 1.7, color: "var(--d-muted)" }}>
          {SOURCES.perRecord.label} · {SOURCES.perRecord.source}
        </p>

        <div style={{ marginTop: 18, display: "grid", gap: 10 }}>
          {estimates.map((e) => (
            <div
              key={e.table}
              style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 16,
                flexWrap: "wrap",
                borderTop: "1px solid var(--d-line)",
                paddingTop: 10,
              }}
            >
              <span style={{ fontSize: 13.5 }}>
                <span className="dxd-mono">{e.table}</span>
                <span style={{ color: "var(--d-muted)" }}> · {e.categories.join(", ")}</span>
              </span>
              <span className="dxd-mono" style={{ fontSize: 12.5, color: "var(--d-muted)", whiteSpace: "nowrap" }}>
                {e.arithmetic.split(" = ")[0]} = {formatMoney(e.estimate)}
              </span>
            </div>
          ))}
        </div>

        {/* Guardrail 6 made visible: the gap is named so the total never reads
            as complete. */}
        {uncountedTables.length > 0 && (
          <p style={{ margin: "16px 0 0", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
            Not included: {uncountedTables.join(", ")} — {uncountedTables.length === 1 ? "it holds" : "they hold"}{" "}
            personal data but we could not count the rows, and we do not estimate them.
          </p>
        )}

        {/* Renders with the number, never as a detachable footnote. */}
        <p style={{ margin: "16px 0 0", fontSize: 12.5, lineHeight: 1.75, color: "var(--d-muted)" }}>
          {estimates[0].caveat}
        </p>

        <p style={{ margin: "12px 0 0", fontSize: 12.5, lineHeight: 1.75, color: "var(--d-muted)" }}>
          {regulatoryNote}
        </p>
      </div>
    </section>
  );
}
