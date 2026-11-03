import type { ProviderCoverageItem } from "@/lib/monitoring/providerCoverage";

// What each connected provider's latest read covered. Unread and
// failed reads are shown as such, never as quiet.
const STATE: Record<ProviderCoverageItem["state"], string> = {
  complete: "Read completely",
  partial: "Partly read",
  failed: "Last read failed",
  never_read: "Not read yet",
  stale_connection: "Not read since reconnecting",
};

const utc = (iso: string) => iso.slice(0, 16).replace("T", " ") + " UTC";

export function ProviderCoverage({ coverage }: { coverage: { available: boolean; items: ProviderCoverageItem[] } }) {
  if (!coverage.available) return <p>We could not load provider read history. What was read is unknown.</p>;
  if (coverage.items.length === 0) {
    return <p className="v3-small">No provider is connected. Findings come from your code alone until you connect one in Settings.</p>;
  }
  return (
    <ul className="v3-small">
      {coverage.items.map((item) => (
        <li key={item.transport} style={{ marginBottom: 12 }}>
          <strong>{item.label}</strong>: {STATE[item.state]}
          {item.observedAt ? <>, <time dateTime={item.observedAt}>{utc(item.observedAt)}</time></> : null}
          <br />
          {item.detail}
          {item.notRead.length > 0 ? <><br />Not read: {item.notRead.join(", ")}.</> : null}
        </li>
      ))}
    </ul>
  );
}
