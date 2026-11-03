import type { AiPause } from "@/lib/intelligence/activity";

/**
 * The security loop (Felipe 2026-10-06): read, attack, map, fix, then watch
 * with traffic and cross-layer context, each shown as it happens. Built only
 * from facts the dashboard already holds; a stage that has not happened says
 * so, a stage waiting on the customer's agent says it waits, and nothing here
 * says an app is secure.
 */
export type LoopState = "done" | "working" | "waiting" | "attention" | "off";
export type LoopStage = {
  key: "read" | "attack" | "map" | "fix" | "watch";
  title: "Read" | "Attack" | "Map" | "Fix" | "Watch";
  state: LoopState; headline: string; detail: string; href: string; action?: string;
};
export type LoopInput = {
  current: { status: "queued" | "running"; step: string | null } | null;
  finished: { status: "complete" | "failed"; filesRead: number; entries: number; tables: number; unread: number } | null;
  agent: { available: boolean; paused: AiPause; pending: number; answered: number };
  map: { routes: number; exposed: number } | null;
  fix: { open: number; withPr: number };
  watch: { prChecks: number; blockedPrs: number; trafficSites: number; hotRoutes: number; hotWithIssue: number; hotWithReview: number; providersRead: number; providersConnected: number };
};

const n = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;
const FIRST = "Waits for the first audit.";

function read({ current, finished }: LoopInput): LoopStage {
  const at = { key: "read", title: "Read", href: "/dashboard/activity" } as const;
  if (current) return { ...at, state: "working", headline: current.status === "queued" ? "Queued" : "Reading now",
    detail: current.step ?? (current.status === "queued" ? "Waiting for a worker to pick it up." : "Starting the read-only checkout.") };
  if (!finished) return { ...at, href: "/dashboard", state: "off", headline: "Not audited",
    detail: "A read-only checkout of your repository, every deterministic check.", action: "Run an audit" };
  if (finished.status === "failed") return { ...at, state: "attention", headline: "Last audit stopped", detail: "Open Activity to read where it stopped." };
  return { ...at, state: "done", headline: n(finished.filesRead, "file") + " read",
    detail: `${n(finished.entries, "entry", "entries")} · ${n(finished.tables, "table")} · ${finished.unread > 0 ? `${n(finished.unread, "area")} not checked` : "every area checked"}` };
}

function attack({ finished, agent }: LoopInput): LoopStage {
  const at = { key: "attack", title: "Attack", href: "/dashboard/coverage" } as const;
  if (!finished) return { ...at, state: "off", headline: "Not run", detail: FIRST };
  if (!agent.available) return { ...at, state: "attention", headline: "Unknown", detail: "Your agent's activity could not be read." };
  if (agent.paused === "not_connected") return { ...at, href: "/dashboard/settings", state: "off", headline: "Not run",
    detail: "Attack reasoning runs on your own agent over MCP. ShipLock makes no AI calls.", action: "Connect your agent" };
  if (agent.paused) return { ...at, href: "/dashboard/settings", state: "attention", headline: "Paused",
    detail: agent.paused === "revoked" ? "Your agent's approval was withdrawn." : "Today's task budget is used up." };
  if (agent.pending > 0) return { ...at, state: "waiting", headline: `${n(agent.pending, "task")} ${agent.pending === 1 ? "waits" : "wait"} for your agent`,
    detail: "They run when your agent picks them up; until then they count as not run." };
  if (agent.answered > 0) return { ...at, state: "done", headline: `${n(agent.answered, "answer")} checked`,
    detail: "Only claims proved by quoted lines in your code become issues." };
  return { ...at, state: "waiting", headline: "Ready", detail: "Your agent is connected. The next audit asks it to attack the routes it finds." };
}

function map({ map }: LoopInput): LoopStage {
  const at = { key: "map", title: "Map", href: "/dashboard#map" } as const;
  if (!map) return { ...at, state: "off", headline: "No map yet", detail: "The map is drawn from an audit's route facts." };
  return { ...at, state: map.exposed > 0 ? "attention" : "done", headline: `${n(map.routes, "route")} mapped`,
    detail: map.exposed > 0 ? `${map.exposed} exposed` : "None exposed in the code read" };
}

function fix({ finished, fix }: LoopInput): LoopStage {
  const at = { key: "fix", title: "Fix", href: "/dashboard/risks" } as const;
  if (!finished) return { ...at, state: "off", headline: "Nothing to fix yet", detail: FIRST };
  if (fix.open === 0) return { ...at, state: "done", headline: "No open issues", detail: "In the code the last audit read." };
  return { ...at, state: "attention", headline: n(fix.open, "open issue"), action: "View issues",
    detail: fix.withPr > 0 ? `${fix.withPr} with a fix pull request` : "Each one offers a fix you review before a pull request opens." };
}

function watch({ finished, watch: w }: LoopInput): LoopStage {
  const at = { key: "watch", title: "Watch", href: "/dashboard/coverage" } as const;
  if (!finished) return { ...at, state: "off", headline: "Not watching yet", detail: FIRST };
  const parts = [
    `${n(w.prChecks, "pull request")} checked${w.blockedPrs > 0 ? `, ${w.blockedPrs} blocked` : ""}`,
    w.trafficSites > 0 ? `traffic from ${n(w.trafficSites, "site")}` : "no traffic connected",
    w.providersRead > 0 ? `${n(w.providersRead, "provider")} read live` : w.providersConnected > 0 ? "providers connected, not read yet" : "no provider connected",
  ];
  const attention = w.hotRoutes > 0 || w.blockedPrs > 0;
  // Watched with the attack's context. A route under attack that the
  // audit found an issue on leads, and points at the issue.
  if (w.hotWithIssue > 0) {
    return { key: "watch", title: "Watch", href: "/dashboard/risks", state: "attention", action: "View issues",
      headline: `${n(w.hotWithIssue, "route")} under attack ${w.hotWithIssue === 1 ? "has" : "have"} an open issue`, detail: parts.join(" · ") };
  }
  // A candidate is not an issue, but traffic on it is a reason to review it first.
  if (w.hotWithReview > 0) {
    return { key: "watch", title: "Watch", href: "/dashboard/risks", state: "attention", action: "Review first",
      headline: `${n(w.hotWithReview, "route")} under attack ${w.hotWithReview === 1 ? "has" : "have"} a finding to review`, detail: parts.join(" · ") };
  }
  return { ...at, state: attention ? "attention" : "done",
    headline: w.hotRoutes > 0 ? `${n(w.hotRoutes, "route")} hit hard` : "Watching pull requests", detail: parts.join(" · ") };
}

/** The five loop stages (Read, Attack, Map, Fix, Watch), each with its real
 * state. */
export function securityLoop(input: LoopInput): LoopStage[] {
  return [read(input), attack(input), map(input), fix(input), watch(input)];
}
