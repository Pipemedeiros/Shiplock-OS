// Shown the moment a dashboard tab is clicked, while the page's data loads.
// The sidebar stays; only the content area is replaced. Also what Next
// prefetches, so navigation between tabs is immediate.
export default function Loading() {
  return (
    <div role="status" aria-busy="true" aria-live="polite" className="v3-loading">
      <span className="v3-sr">Loading</span>
      <div className="v3-skel" style={{ width: 180, height: 11 }} />
      <div className="v3-skel" style={{ width: "min(420px, 80%)", height: 30, marginTop: 14 }} />
      <div className="v3-skel" style={{ height: 220, marginTop: 28 }} />
      <div className="v3-grid-2" style={{ marginTop: 18 }}>
        <div className="v3-skel" style={{ height: 140 }} />
        <div className="v3-skel" style={{ height: 140 }} />
      </div>
    </div>
  );
}
