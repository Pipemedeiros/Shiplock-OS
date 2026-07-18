// Embeddable "Secured by ShipLock" badge — a self-contained copy-paste HTML
// snippet (an <a> to the live report wrapping an inline SVG, no hotlinked
// image) the customer drops on their own site. Every badge links back to the
// live report → the distribution loop.

// The badge MARK is a placeholder shield today. Logo is still an open decision
// (CLAUDE.md), so this is the single point to swap when it lands — replace
// BADGE_MARK with the final logo's inline SVG and nothing else changes.
const BADGE_MARK =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
  '<path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="#4ade80"/>' +
  '<path d="m9 12 2 2 4-4" stroke="#0b1220" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' +
  "</svg>";

export function reportUrl(token: string, appUrl: string): string {
  return `${appUrl.replace(/\/+$/, "")}/verified/${token}`;
}

/**
 * Returns an HTML snippet the customer pastes into their site. Inline styles
 * only (works anywhere, no external CSS/JS), opens the live report in a new tab.
 */
export function buildBadgeSnippet(token: string, appUrl: string): string {
  const href = reportUrl(token, appUrl);
  return (
    `<a href="${href}" target="_blank" rel="noopener noreferrer" ` +
    `style="display:inline-flex;align-items:center;gap:6px;padding:6px 10px;` +
    `border:1px solid #1f2a3a;border-radius:8px;background:#0b1220;color:#e6edf6;` +
    `font:600 12px/1 system-ui,sans-serif;text-decoration:none;">` +
    `${BADGE_MARK}<span>Secured by ShipLock</span></a>`
  );
}
