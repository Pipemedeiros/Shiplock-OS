import type { Severity } from "@/lib/types";

// Distributed application-layer flood detection.
//
// This is the half of "DDoS" that is genuinely ours, and until now we did not
// cover it. The existing detector works per SOURCE: one address making many
// requests gets blocked. A distributed flood defeats that by construction —
// 2,000 addresses making five requests each trip no per-source threshold, and
// the customer's database still runs out of connections.
//
// It is also the shape that actually reaches this ICP. Volumetric attacks are
// absorbed upstream by the host's network for free; what passes through is
// traffic that looks individually legitimate. A CDN forwards it because each
// request IS legitimate. The damage is done by the aggregate hitting an endpoint
// that costs 200ms of Postgres, not by bandwidth.
//
// WHY THE BASELINE MATTERS MORE THAN THE THRESHOLD: a fixed "requests per
// second" limit is wrong for everybody. It is far too low for an app being
// featured somewhere and far too high for one with nine users. So this compares
// against the app's OWN recent history, and refuses to judge at all until it has
// enough history to compare against. A launch is not an attack, and the
// difference is visible in the shape — a launch brings many sources to many
// pages, an attack brings many sources to one expensive one.

export interface TrafficWindow {
  /** Requests in this window. */
  requests: number;
  /** Distinct sources seen. */
  sources: number;
  /** Requests to the single busiest path. */
  topPathRequests: number;
  /** The busiest path itself. */
  topPath: string;
}

export interface SurgeAssessment {
  /** True when the current window is a genuine anomaly against baseline. */
  surging: boolean;
  /** How many times the baseline rate. */
  multiple: number;
  /** Distributed (many sources) or concentrated (few). */
  distributed: boolean;
  /** Share of traffic hitting one path — high means targeted, not organic. */
  concentration: number;
  /** Why we did or did not call it. */
  reason: string;
}

/** Below this, there is not enough history to say anything is abnormal. */
const MIN_BASELINE_WINDOWS = 6;
const MIN_BASELINE_REQUESTS = 50;
/** A surge must be this many times the baseline before it counts. */
const SURGE_MULTIPLE = 5;
/** One path taking this share of traffic is targeting, not browsing. */
const TARGETED_CONCENTRATION = 0.6;
/** More sources than this makes per-source blocking ineffective. */
const DISTRIBUTED_SOURCES = 50;

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/**
 * Is the current window an attack?
 *
 * Median rather than mean for the baseline, so one previous spike does not raise
 * the bar and hide the next one.
 */
export function assessSurge(current: TrafficWindow, baseline: TrafficWindow[]): SurgeAssessment {
  const concentration = current.requests > 0 ? current.topPathRequests / current.requests : 0;
  const distributed = current.sources >= DISTRIBUTED_SOURCES;

  const quiet: SurgeAssessment = {
    surging: false,
    multiple: 0,
    distributed,
    concentration,
    reason: "",
  };

  // Not enough history to know what normal looks like. Guessing here would mean
  // calling a new customer's first busy hour an attack.
  if (baseline.length < MIN_BASELINE_WINDOWS) {
    return { ...quiet, reason: "Not enough history yet to know what your normal traffic looks like." };
  }

  const baselineMedian = median(baseline.map((w) => w.requests));
  if (baselineMedian < MIN_BASELINE_REQUESTS) {
    return { ...quiet, reason: "Traffic is too low for a rate comparison to mean anything." };
  }

  const multiple = current.requests / baselineMedian;
  if (multiple < SURGE_MULTIPLE) {
    return { ...quiet, multiple, reason: "Within normal range for this app." };
  }

  // A surge spread across many pages is a launch, a crawl, or a good day.
  // A surge concentrated on one path is someone hammering one endpoint.
  if (concentration < TARGETED_CONCENTRATION) {
    return {
      ...quiet,
      multiple,
      reason: `Traffic is ${multiple.toFixed(1)}x normal but spread across your site, which looks like real attention rather than an attack.`,
    };
  }

  return {
    surging: true,
    multiple,
    distributed,
    concentration,
    reason: `${multiple.toFixed(1)}x normal traffic, ${Math.round(concentration * 100)}% of it on ${current.topPath}.`,
  };
}

export interface SurgeFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
}

/**
 * What we tell the customer, and what we did about it.
 *
 * The distributed case is the one worth separating, because it is the case where
 * our normal response does not work and saying so is more useful than implying
 * it is handled.
 */
export function describeSurge(current: TrafficWindow, assessment: SurgeAssessment): SurgeFinding[] {
  if (!assessment.surging) return [];

  const shared =
    `${current.requests.toLocaleString()} requests reached ${current.topPath} from ${current.sources.toLocaleString()} sources — ${assessment.multiple.toFixed(1)} times your normal rate, with ${Math.round(assessment.concentration * 100)}% of all traffic on that one path. ` +
    `Real growth arrives across a site; this arrived at one endpoint.`;

  if (assessment.distributed) {
    return [
      {
        id: `traffic:distributed_flood:${current.topPath}`,
        severity: "CRITICAL",
        title: `${current.topPath} is under a distributed flood`,
        consequence:
          `${shared} ` +
          `Because it is spread across ${current.sources.toLocaleString()} sources, blocking individual addresses will not stop it — each one is making too few requests to look wrong on its own, which is the point of doing it this way. ` +
          `What is at risk is not your bandwidth but your database: an endpoint that costs a query per request runs out of connections long before the network notices anything. ` +
          `We have started turning away requests to ${current.topPath} that arrive faster than your normal rate, which keeps the rest of your app serving. That is reversible from your dashboard and lifts by itself once the rate returns to normal. ` +
          `The durable fix is caching or a rate limit on that endpoint specifically — if it does not need to be computed per request, it should not be.`,
      },
    ];
  }

  return [
    {
      id: `traffic:concentrated_flood:${current.topPath}`,
      severity: "WARNING",
      title: `${current.topPath} is taking an unusual amount of traffic`,
      consequence:
        `${shared} ` +
        `It is coming from few enough sources that the ones responsible have been blocked, which normally ends it. ` +
        `Worth a look at whether that endpoint is expensive to serve — a path that hits the database on every request is the one an attacker returns to, because it costs them a request and costs you a query.`,
    },
  ];
}

/**
 * Which paths to shed first when the app is under pressure.
 *
 * The point is to degrade rather than fall over. Auth and payment paths are kept
 * serving to the end, because an app that stays up but cannot let anyone log in
 * or pay has failed in the way that actually costs the customer money — and
 * shedding those is how a defence becomes the outage.
 */
const NEVER_SHED = /^\/(api\/)?(auth|login|signin|signup|logout|session|checkout|billing|webhook|stripe)/i;

export function shouldShed(path: string, underSurge: boolean): boolean {
  if (!underSurge) return false;
  if (NEVER_SHED.test(path)) return false;
  return true;
}

/**
 * The autonomous response, graded by the doctrine's ladder.
 *
 * Rate-limiting one path under a measured surge is Tier 1: reversible in
 * seconds, blast radius bounded to a single endpoint, and it lifts itself when
 * the traffic does. It is the same category as blocking a credential-stuffing
 * source, which already acts without asking.
 */
export interface SurgeResponse {
  action: "none" | "throttle_path";
  path?: string;
  /** Requests per minute allowed through while the surge lasts. */
  allowancePerMinute?: number;
  reversible: true;
  explanation: string;
}

export function planResponse(
  current: TrafficWindow,
  assessment: SurgeAssessment,
  baseline: TrafficWindow[]
): SurgeResponse {
  if (!assessment.surging) {
    return { action: "none", reversible: true, explanation: assessment.reason };
  }

  // Allow the app's own normal rate for that path, not an arbitrary number, so
  // legitimate users are unaffected and only the excess is turned away.
  const baselineMedian = median(baseline.map((w) => w.topPathRequests));
  const allowance = Math.max(60, Math.ceil(baselineMedian * 1.5));

  return {
    action: "throttle_path",
    path: current.topPath,
    allowancePerMinute: allowance,
    reversible: true,
    explanation:
      `Allowing ${allowance} requests a minute to ${current.topPath} — about 1.5x its own normal rate — and turning away the excess. ` +
      `Your real users are inside that budget; the flood is not. Lifts automatically when the rate returns to normal, and can be turned off from the dashboard.`,
  };
}
