// Badge install verification.
//
// The Verified badge is an attestation the customer publishes on their own
// site, and an attestation nobody checks is worth nothing — anyone could paste
// the markup without ShipLock ever monitoring anything. So we confirm the
// backlink actually exists: fetch the customer's app URL (which we already
// persist, migration 032) and look for a link to their own report.
//
// Deliberately narrow. This proves "a page at this address links to this
// report", nothing more. It is not proof the badge is visible, on every page,
// or above the fold — and it must never be described as more than it is.
//
// Fail-soft by design: a site that's down, slow, client-rendered, or behind a
// bot wall returns "unknown", never "missing". A false "not installed" accuses
// a paying customer of something untrue, which is worse than no signal.

const FETCH_TIMEOUT_MS = 6000;
const MAX_BYTES = 512_000; // enough for any reasonable <head>+<body> start

export type BadgeInstallState = "installed" | "not_found" | "unknown";

export interface BadgeCheckResult {
  state: BadgeInstallState;
  /** Why, for the dashboard to explain honestly rather than just show a cross. */
  detail: string;
  checkedAt: string;
}

/**
 * Does `appUrl`'s HTML contain a link to `reportUrl`?
 *
 * Matches on the token path rather than the full URL so a customer who links
 * through a different host alias, or omits the protocol, still verifies.
 */
export async function checkBadgeInstalled(
  appUrl: string,
  token: string
): Promise<BadgeCheckResult> {
  const checkedAt = new Date().toISOString();

  let target: URL;
  try {
    target = new URL(appUrl);
  } catch {
    return { state: "unknown", detail: "No valid app URL on file.", checkedAt };
  }
  if (target.protocol !== "https:" && target.protocol !== "http:") {
    return { state: "unknown", detail: "App URL isn't a web address.", checkedAt };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(target.toString(), {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        // Identify ourselves honestly — this is our own automated request to a
        // customer's site, made with their permission (see /terms).
        "user-agent": "ShipLock-BadgeCheck/1.0 (+https://shiplock.dev)",
        accept: "text/html,application/xhtml+xml",
      },
    });

    if (!res.ok) {
      return {
        state: "unknown",
        detail: `Your site answered ${res.status}, so we couldn't check.`,
        checkedAt,
      };
    }

    const contentType = res.headers.get("content-type") ?? "";
    if (!contentType.includes("html")) {
      return { state: "unknown", detail: "That address didn't return a web page.", checkedAt };
    }

    const html = (await res.text()).slice(0, MAX_BYTES);

    if (html.includes(`/verified/${token}`)) {
      return { state: "installed", detail: "Badge found, linking to your report.", checkedAt };
    }

    // A link to some OTHER ShipLock report is worth calling out separately —
    // usually a copy-paste from someone else's site.
    if (/\/verified\/[A-Za-z0-9_-]{8,}/.test(html)) {
      return {
        state: "not_found",
        detail: "Found a ShipLock badge, but it links to a different report.",
        checkedAt,
      };
    }

    return {
      state: "not_found",
      detail: "No badge found on your homepage. If it's on another page, that's fine; we only check this one.",
      checkedAt,
    };
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    return {
      state: "unknown",
      detail: aborted
        ? "Your site took too long to answer, so we couldn't check."
        : "We couldn't reach your site to check.",
      checkedAt,
    };
  } finally {
    clearTimeout(timer);
  }
}
