import type { WatchLogEntry, WatchStatus } from "@/lib/monitoring/watchLog";
import type { ScanTimelineEntry } from "@/lib/scanHistory";

// Presentational, server-safe (no hooks) — renders the watch's own activity
// record and the audit history. Everything shown here is counts/metadata
// only; paywall-sensitive content (fix/codefix) never reaches these props.

const TRIGGER_LABELS: Record<WatchLogEntry["trigger"], string> = {
  manual: "manual audit · 16 checks",
  deploy: "deploy re-scan · 16 checks",
  hourly: "hourly pass · critical checks",
  scheduled_48h: "deep scan · 16 checks",
};

const DEEP_SCAN_INTERVAL_MS = 48 * 60 * 60 * 1000;

function formatWhen(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function EntryResult({ entry }: { entry: WatchLogEntry }) {
  if (entry.newCount === null) {
    return <span style={{ color: "var(--d-muted)" }}>baseline · {entry.findingCount} open</span>;
  }
  if (entry.newCount > 0) {
    return (
      <span className="dxd-chip dxd-chip-critical">
        +{entry.newCount} new
      </span>
    );
  }
  return <span style={{ color: "var(--d-muted)" }}>nothing new · {entry.findingCount} open</span>;
}

export function WatchPanel({
  entries,
  status,
  timeline,
  webhookUrl,
}: {
  entries: WatchLogEntry[];
  status: WatchStatus;
  timeline: ScanTimelineEntry[];
  webhookUrl: string | null;
}) {
  const lastEvent = entries[0]?.createdAt ?? null;
  const nextDeepDue = status.lastDeepScanAt
    ? new Date(new Date(status.lastDeepScanAt).getTime() + DEEP_SCAN_INTERVAL_MS).toISOString()
    : null;

  return (
    <section style={{ marginTop: 40 }} aria-label="The watch — engagement record">
      <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
        The watch · engagement record
      </p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20 }}>
        <div className="dxd-surface">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14 }}>
            <h3 style={{ margin: 0, fontSize: 15 }}>Watch log</h3>
            <span className="dxd-mono" style={{ fontSize: 11, color: status.enabled ? "var(--d-bronze)" : "var(--d-muted)" }}>
              {status.enabled ? "● watching" : "○ paused"}
            </span>
          </div>
          {entries.length > 0 ? (
            <>
              <div className="dxd-mono" style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12 }}>
                {entries.map((e) => (
                  <div
                    key={`${e.trigger}-${e.createdAt}`}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 12,
                      borderBottom: "1px solid var(--d-line)",
                      padding: "6px 0",
                    }}
                  >
                    <span style={{ color: "var(--d-muted)", whiteSpace: "nowrap" }}>{formatWhen(e.createdAt)}</span>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {TRIGGER_LABELS[e.trigger]}
                    </span>
                    <EntryResult entry={e} />
                  </div>
                ))}
              </div>
              <p style={{ marginTop: 12, marginBottom: 0, fontSize: 11.5, lineHeight: 1.6, color: "var(--d-muted)" }}>
                Every pass the watch runs, logged — silence up there means checks ran and found
                nothing new. Last event {formatWhen(lastEvent)}
                {nextDeepDue ? `; next full deep scan due by ${formatWhen(nextDeepDue)}.` : "; first full deep scan runs on the next 48-hour cycle."}
              </p>
            </>
          ) : (
            <p style={{ margin: 0, fontSize: 13, lineHeight: 1.7, color: "var(--d-muted)" }}>
              No watch activity recorded yet. The watch enrolls with your next audit — from then
              on, hourly critical passes, deploy re-scans, and 48-hour deep scans land here as
              they run.
            </p>
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div className="dxd-surface">
            <h3 style={{ margin: "0 0 14px", fontSize: 15 }}>Audit history</h3>
            {timeline.length > 0 ? (
              <div className="dxd-mono" style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12 }}>
                {timeline.map((t, i) => {
                  const prev = timeline[i + 1];
                  const delta =
                    prev && t.issue_count !== null && prev.issue_count !== null
                      ? t.issue_count - prev.issue_count
                      : null;
                  return (
                    <div
                      key={`${t.created_at}-${i}`}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 12,
                        borderBottom: "1px solid var(--d-line)",
                        padding: "6px 0",
                      }}
                    >
                      <span style={{ color: "var(--d-muted)" }}>{formatWhen(t.created_at)}</span>
                      <span className="dxd-serif" style={{ fontSize: 16, fontWeight: 700 }}>
                        {t.grade ?? "—"}
                      </span>
                      <span style={{ color: "var(--d-muted)" }}>
                        {t.issue_count ?? "—"} issues
                        {delta !== null && delta !== 0 && (
                          <span style={{ color: delta < 0 ? "var(--d-bronze)" : "var(--d-muted)" }}>
                            {" "}
                            ({delta < 0 ? "" : "+"}
                            {delta})
                          </span>
                        )}
                      </span>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p style={{ margin: 0, fontSize: 13, color: "var(--d-muted)" }}>
                Your audits will accumulate here — grade and open-issue count, every run.
              </p>
            )}
          </div>

          {webhookUrl && (
            <div className="dxd-surface">
              <h3 style={{ margin: "0 0 10px", fontSize: 15 }}>Every deploy, re-audited</h3>
              <p style={{ margin: "0 0 12px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
                Add this webhook once in your Vercel project — Settings → Webhooks, event
                “Deployment Ready”, production — and every deploy triggers an immediate re-scan.
                The address is unique to your account; treat it like a password.
              </p>
              <p
                className="dxd-mono"
                style={{
                  margin: 0,
                  fontSize: 11.5,
                  wordBreak: "break-all",
                  background: "var(--d-porcelain)",
                  border: "1px solid var(--d-line)",
                  borderRadius: 8,
                  padding: "10px 12px",
                  userSelect: "all",
                }}
              >
                {webhookUrl}
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
