import { z } from "zod";

export const SupabaseBindingCollector = z.enum(["supabase-management", "supabase-scan"]);
export type SupabaseBindingCollector = z.infer<typeof SupabaseBindingCollector>;
const id = z.uuid(), numericId = z.string().regex(/^[1-9]\d*$/), projectRef = z.string().min(1).max(63).regex(/^[a-z0-9-]+$/);
const repository = z.object({ id, fullName: z.string().regex(/^[\w.-]+\/[\w.-]+$/), githubRepoId: numericId.nullable() });
const binding = z.object({ repositoryId: id, method: z.literal("customer_confirmed"), confirmedAt: z.iso.datetime({ offset: true }) });
function responseSchema(collector: SupabaseBindingCollector) {
  return z.union([
    z.object({ available: z.literal(true), collector: z.literal(collector), projectRef,
      endpointUrl: z.string().regex(/^https:\/\/[a-z0-9-]+\.supabase\.co$/).nullable(),
      connectionFingerprint: z.string().regex(/^[a-f0-9]{64}$/), installationId: numericId,
      githubConnectedAt: z.iso.datetime({ offset: true }), repositories: z.array(repository), bindings: z.array(binding),
    }).refine((value) => (collector === "supabase-management" ? value.endpointUrl === null
      : value.endpointUrl === `https://${value.projectRef}.supabase.co`) &&
      new Set(value.repositories.map((item) => item.id)).size === value.repositories.length &&
      new Set(value.repositories.map((item) => item.fullName.toLowerCase())).size === value.repositories.length &&
      new Set(value.repositories.filter((item) => item.githubRepoId !== null).map((item) => item.githubRepoId)).size ===
        value.repositories.filter((item) => item.githubRepoId !== null).length &&
      new Set(value.bindings.map((item) => item.repositoryId)).size === value.bindings.length &&
      Date.parse(value.githubConnectedAt) <= Date.now() && value.bindings.every((item) =>
        Date.parse(item.confirmedAt) >= Date.parse(value.githubConnectedAt) && Date.parse(item.confirmedAt) <= Date.now() &&
        value.repositories.some((candidate) => candidate.id === item.repositoryId))),
    z.object({ available: z.literal(false), collector: z.literal(collector), repositories: z.array(z.never()), bindings: z.array(z.never()) }),
  ]);
}
export type SupabaseRepositoryContext = Extract<z.infer<ReturnType<typeof responseSchema>>, { available: true }>;
type Decision = { repositoryId: string; action: "confirm" | "remove" };
export interface SupabaseRepositoryConfirmationState {
  status: "loading" | "ready" | "review" | "saving" | "unconfigured" | "unavailable" | "stale";
  context?: SupabaseRepositoryContext; decision?: Decision; message?: string;
}
const initial: SupabaseRepositoryConfirmationState = { status: "loading" };

/** Transport-local client state. It never retries a mutation or accepts an
 * acknowledgement without rereading the exact project/repository identity. */
export function createSupabaseRepositoryConfirmation(collector: SupabaseBindingCollector,
  transport: typeof fetch = (...args) => fetch(...args)) {
  const schema = responseSchema(collector);
  const acknowledgement = z.object({ ok: z.literal(true), collector: z.literal(collector), method: z.literal("customer_confirmed") });
  const path = `/api/deep/supabase/repository?collector=${collector}`;
  let state = initial, sequence = 0; let request: AbortController | undefined;
  const listeners = new Set<() => void>();
  const update = (next: SupabaseRepositoryConfirmationState) => { state = next; for (const listener of listeners) listener(); };
  const begin = () => { request?.abort(); request = new AbortController(); return { sequence: ++sequence, signal: request.signal }; };
  const current = (operation: { sequence: number }) => operation.sequence === sequence;
  async function read(signal: AbortSignal) {
    const response = await transport(path, { method: "GET", credentials: "same-origin", cache: "no-store", signal });
    if (!response.ok) throw new Error("Context unavailable");
    return schema.parse(await response.json());
  }
  return {
    getSnapshot: () => state, getServerSnapshot: () => initial,
    subscribe: (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; },
    suspend: () => { ++sequence; request?.abort(); update(initial); },
    async load() {
      if (state.status === "saving") return;
      const operation = begin(); update(initial);
      try { const context = await read(operation.signal); if (current(operation)) update(context.available ? { status: "ready", context } : { status: "unconfigured" }); }
      catch { if (current(operation)) update({ status: "unavailable", message: "Repository associations are unavailable. Reload to try again." }); }
    },
    review(repositoryId: string, action: Decision["action"]) {
      if (state.status !== "ready" || !state.context?.repositories.some((item) => item.id === repositoryId)) return;
      const confirmed = state.context.bindings.some((item) => item.repositoryId === repositoryId);
      if (confirmed !== (action === "remove")) return;
      update({ status: "review", context: state.context, decision: { repositoryId, action } });
    },
    cancel() { if (state.status === "review") update({ status: "ready", context: state.context }); },
    async approve() {
      const { context, decision } = state;
      if (state.status !== "review" || !context || !decision) return;
      const selected = context.repositories.find((item) => item.id === decision.repositoryId); if (!selected) return;
      const operation = begin(); update({ status: "saving", context, decision });
      try {
        const response = await transport("/api/deep/supabase/repository", { method: "POST", credentials: "same-origin", signal: operation.signal,
          headers: { "content-type": "application/json" }, body: JSON.stringify({ action: decision.action, confirmed: true, collector,
            repositoryId: selected.id, expectedProjectRef: context.projectRef, expectedEndpointUrl: context.endpointUrl,
            expectedConnectionFingerprint: context.connectionFingerprint, expectedInstallationId: context.installationId,
            expectedGithubConnectedAt: context.githubConnectedAt, expectedRepositoryFullName: selected.fullName,
            expectedGithubRepositoryId: selected.githubRepoId }) });
        if (!current(operation)) return;
        if (response.status === 409) { update({ status: "stale", message: "The connection or repository changed. Reload the list and review again." }); return; }
        if (!response.ok) throw new Error("Change unavailable");
        acknowledgement.parse(await response.json()); if (!current(operation)) return;
        const after = await read(operation.signal); if (!current(operation)) return;
        const afterRepository = after.available ? after.repositories.find((item) => item.id === selected.id) : undefined;
        if (!after.available || !afterRepository || after.collector !== context.collector || after.projectRef !== context.projectRef ||
            after.endpointUrl !== context.endpointUrl || after.connectionFingerprint !== context.connectionFingerprint ||
            after.installationId !== context.installationId || after.githubConnectedAt !== context.githubConnectedAt ||
            afterRepository.fullName !== selected.fullName || afterRepository.githubRepoId !== selected.githubRepoId) {
          update({ status: "stale", message: "The connection or repository changed. Reload the list and review again." }); return;
        }
        const confirmed = after.bindings.some((item) => item.repositoryId === selected.id);
        if (confirmed !== (decision.action === "confirm")) throw new Error("Change not corroborated");
        update({ status: "ready", context: after, message: decision.action === "confirm" ? "Association confirmed by you." : "Association removed." });
      } catch { if (current(operation)) update({ status: "unavailable", message: "We couldn't verify the saved association. Reload the list before trying again." }); }
    },
  };
}
