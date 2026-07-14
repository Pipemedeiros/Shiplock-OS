import type { BlockedSource, ProtectionStatus } from "@/lib/types";
import type { ThreatAlert } from "@/lib/traffic/trafficLog";
import { EdgeSnippet } from "./EdgeSnippet";

// Presentational, server-safe (no hooks). Everything here is counts/metadata
// only — source_id is a salted hash, never a raw IP, and no request bodies or
// paths-with-secrets reach these props.

function formatWhen(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function activeState(expiresAt: string): boolean {
  const ts = Date.parse(expiresAt);
  return !Number.isNaN(ts) && ts > Date.now();
}

export function TrafficPanel({
  status,
  blocks,
  threats,
  snippet,
  webSnippet,
  expressSnippet,
}: {
  status: ProtectionStatus;
  blocks: BlockedSource[];
  threats: ThreatAlert[];
  snippet: string;
  webSnippet: string;
  expressSnippet: string;
}) {
  return (
    <section style={{ marginTop: 40 }} aria-label="Live traffic protection">
      <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
        Live traffic protection · the edge
      </p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 20 }}>
        <div className="dxd-surface">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14 }}>
            <h3 style={{ margin: 0, fontSize: 15 }}>Threats blocked</h3>
            <span
              className="dxd-mono"
              style={{ fontSize: 11, color: status.installed ? "var(--d-bronze)" : "var(--d-muted)" }}
            >
              {status.installed ? "● protecting" : "○ not installed"}
            </span>
          </div>

          {blocks.length > 0 ? (
            <>
              <div className="dxd-mono" style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12 }}>
                {blocks.map((b) => (
                  <div
                    key={`${b.sourceId}-${b.blockedAt}`}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      gap: 12,
                      borderBottom: "1px solid var(--d-line)",
                      padding: "6px 0",
                    }}
                  >
                    <span style={{ color: "var(--d-muted)", whiteSpace: "nowrap" }}>{formatWhen(b.blockedAt)}</span>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {b.reason}
                    </span>
                    {activeState(b.expiresAt) ? (
                      <span className="dxd-chip dxd-chip-critical">blocked</span>
                    ) : (
                      <span style={{ color: "var(--d-muted)" }}>lifted</span>
                    )}
                  </div>
                ))}
              </div>
              <p style={{ marginTop: 12, marginBottom: 0, fontSize: 11.5, lineHeight: 1.6, color: "var(--d-muted)" }}>
                Malicious sources are blocked automatically and the block lifts itself after a
                cooldown — a quiet list means nothing hostile is hitting your app right now.
              </p>
            </>
          ) : (
            <p style={{ margin: 0, fontSize: 13, lineHeight: 1.7, color: "var(--d-muted)" }}>
              {status.installed
                ? "Nothing hostile detected. When ShipLock spots credential stuffing, a vulnerability scanner, or a request flood, the source is blocked here automatically."
                : "Not protecting yet — add the snippet below to your app and every request to your login and API routes is watched, with malicious sources blocked automatically."}
            </p>
          )}

          {threats.length > 0 && (
            <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--d-line)" }}>
              <p className="dxd-mono" style={{ margin: "0 0 6px", fontSize: 10.5, color: "var(--d-muted)", textTransform: "uppercase", letterSpacing: 0.5 }}>
                Flagged, not blocked
              </p>
              <div className="dxd-mono" style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11.5 }}>
                {threats.map((t, i) => (
                  <div key={`${t.alertedAt}-${i}`} style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                    <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--d-muted)" }}>
                      {t.reason}
                    </span>
                    <span style={{ color: "var(--d-muted)", whiteSpace: "nowrap" }}>{formatWhen(t.alertedAt)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <p style={{ marginTop: 14, marginBottom: 0, fontSize: 11.5, color: "var(--d-muted)" }}>
            {status.activeBlocks} active · last seen {formatWhen(status.lastSeenAt)}
          </p>
        </div>

        <EdgeSnippet
          snippet={snippet}
          webSnippet={webSnippet}
          expressSnippet={expressSnippet}
          installed={status.installed}
        />
      </div>
    </section>
  );
}
