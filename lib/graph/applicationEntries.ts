import type { RepoFile } from "@/lib/deep/githubScan";
import { collectRoutes, type RouteFact } from "./routeInventory";
import { serverActionRoutes } from "./serverActionFacts";
import { trpcRoutes } from "./trpcProcedures";

/**
 * Every application entry the deep analysis reasons over, in one fact shape:
 * route handlers, server actions the browser can call (7E-3) and tRPC
 * procedures (7G). The audit and the offline evaluator both call this, so the
 * measured population is the audited one.
 */
export function applicationEntries(files: RepoFile[]): { routes: RouteFact[]; actions: number; procedures: number } {
  const actions = serverActionRoutes(files);
  const procedures = trpcRoutes(files);
  return { routes: [...collectRoutes(files), ...actions, ...procedures], actions: actions.length, procedures: procedures.length };
}
