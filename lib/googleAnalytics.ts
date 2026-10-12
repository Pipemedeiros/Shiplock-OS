// Google Analytics 4 for shiplock.dev (Felipe, 2026-10-12: his business
// account is how he watches visitors). Started only from initAnalytics, which
// runs only after the visitor accepts analytics cookies
// (components/CookieConsent.tsx); without NEXT_PUBLIC_GA_MEASUREMENT_ID it does
// nothing. Ad signals are off: visit counts, not advertising.
type Doc = { createElement(tag: "script"): { src: string; async: boolean }; head: { appendChild(node: { src: string; async: boolean }): unknown } };
type Win = { dataLayer?: unknown[]; gtag?: (...args: unknown[]) => void };

const MEASUREMENT_ID = /^G-[A-Z0-9]{4,16}$/;

export function startGoogleAnalytics(doc: Doc, win: Win, id: string | undefined): boolean {
  if (!id || !MEASUREMENT_ID.test(id) || win.gtag) return false;
  const dataLayer = (win.dataLayer ??= []);
  // gtag.js reads `arguments` objects from dataLayer, as Google's snippet pushes them.
  win.gtag = function gtag() {
    // eslint-disable-next-line prefer-rest-params
    dataLayer.push(arguments);
  };
  win.gtag("js", new Date());
  win.gtag("config", id, { allow_google_signals: false, allow_ad_personalization_signals: false });
  const script = doc.createElement("script");
  script.async = true;
  script.src = `https://www.googletagmanager.com/gtag/js?id=${id}`;
  doc.head.appendChild(script);
  return true;
}
