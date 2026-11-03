// Embeddable "Secured by ShipLock" badge — a self-contained copy-paste HTML
// snippet (an <a> to the live report wrapping an inline SVG, no hotlinked
// image) the customer drops on their own site. Every badge links back to the
// live report → the distribution loop.

// The badge MARK is the micro cut of the mark in components/d/Brand.tsx
// (LockGlyphMicro) — the badge renders at 14px on someone else's site, where the
// open keyhole and the diagonal sweep both fill in. Bronze (#c9a961), v3's
// --bronze-l, the accent used on navy, because the badge always sits on the navy
// chip below. Swap here and in Brand.tsx together; nothing else embeds the mark.
const BADGE_MARK =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#c9a961" ' +
  'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" ' +
  'xmlns="http://www.w3.org/2000/svg" aria-hidden="true">' +
  '<path d="M8.4 10.4V7.2a3.6 3.6 0 0 1 7.2 0v3.2"/>' +
  '<path d="M12 8.4 18.4 12.1v7L12 22.8l-6.4-3.7v-7L12 8.4Z"/>' +
  '<circle cx="12" cy="15.4" r="1.35" fill="#c9a961" stroke="none"/>' +
  "</svg>";

/** The public Verified report address for a token. */
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
