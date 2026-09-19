import { z } from "zod";

// Client-safe protocol only. Never import the service-role binding writer,
// credential fingerprint implementation or provider SDK into the UI bundle.
const id = z.uuid();
const numericId = z.string().regex(/^[1-9]\d*$/);
const readySchema = z.object({
  available: z.literal(true), databaseDisplay: z.string().min(1).max(2048), connectionFingerprint: z.string().regex(/^[a-f0-9]{64}$/), installationId: numericId,
  githubConnectedAt: z.iso.datetime({ offset: true }),
  repositories: z.array(z.object({ id, fullName: z.string().regex(/^[\w.-]+\/[\w.-]+$/), githubRepoId: numericId.nullable() })),
  bindings: z.array(z.object({ repositoryId: id, method: z.literal("customer_confirmed"), confirmedAt: z.iso.datetime({ offset: true }) })),
}).refine((value) => new Set(value.repositories.map((repository) => repository.id)).size === value.repositories.length &&
  new Set(value.repositories.map((repository) => repository.fullName.toLowerCase())).size === value.repositories.length &&
  new Set(value.bindings.map((binding) => binding.repositoryId)).size === value.bindings.length &&
  new Set(value.repositories.filter((repository) => repository.githubRepoId !== null).map((repository) => repository.githubRepoId)).size ===
    value.repositories.filter((repository) => repository.githubRepoId !== null).length &&
  Date.parse(value.githubConnectedAt) <= Date.now() && value.bindings.every((binding) =>
    Date.parse(binding.confirmedAt) >= Date.parse(value.githubConnectedAt) && Date.parse(binding.confirmedAt) <= Date.now() &&
    value.repositories.some((repository) => repository.id === binding.repositoryId)));
const contextSchema = z.union([readySchema, z.object({ available: z.literal(false), repositories: z.array(z.never()), bindings: z.array(z.never()) })]);
const acknowledgement = z.object({ ok: z.literal(true), method: z.literal("customer_confirmed") });
export type DirectRepositoryContext = z.infer<typeof readySchema>;
type Decision = { repositoryId: string; action: "confirm" | "remove" };
export interface DirectRepositoryConfirmationState {
  status: "loading" | "ready" | "review" | "saving" | "unconfigured" | "unavailable" | "stale";
  context?: DirectRepositoryContext;
  decision?: Decision;
  message?: string;
}
const initial: DirectRepositoryConfirmationState = { status: "loading" };
const path = "/api/deep/postgres/repository";
const uncertain = "We couldn't verify the saved association. Reload the list before trying again.";

/** Cached external store for React and deterministic local tests. Each new
 * request invalidates old responses. Never optimistically show a confirmation
 * or retry a mutation whose outcome may be uncertain. */
export function createDirectRepositoryConfirmation(transport: typeof fetch = (...args) => fetch(...args)) {
  let state = initial;
  let sequence = 0;
  let request: AbortController | undefined;
  const listeners = new Set<() => void>();
  const update = (next: DirectRepositoryConfirmationState) => { state = next; for (const listener of listeners) listener(); };
  const begin = () => { request?.abort(); request = new AbortController(); return { sequence: ++sequence, signal: request.signal }; };
  const current = (operation: { sequence: number }) => operation.sequence === sequence;
  async function read(signal: AbortSignal) {
    const response = await transport(path, { method: "GET", credentials: "same-origin", cache: "no-store", signal });
    if (!response.ok) throw new Error("Context unavailable");
    return contextSchema.parse(await response.json());
  }
  return {
    getSnapshot: () => state,
    getServerSnapshot: () => initial,
    subscribe: (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; },
    suspend: () => { ++sequence; request?.abort(); update(initial); },
    async load() {
      if (state.status === "saving") return;
      const operation = begin(); update(initial);
      try {
        const context = await read(operation.signal);
        if (current(operation)) update(context.available ? { status: "ready", context } : { status: "unconfigured" });
      } catch {
        if (current(operation)) update({ status: "unavailable", message: "Repository associations are unavailable. Reload to try again." });
      }
    },
    review(repositoryId: string, action: Decision["action"]) {
      if (state.status !== "ready" || !state.context?.repositories.some((repository) => repository.id === repositoryId)) return;
      const confirmed = state.context.bindings.some((binding) => binding.repositoryId === repositoryId);
      if (confirmed !== (action === "remove")) return;
      update({ status: "review", context: state.context, decision: { repositoryId, action } });
    },
    cancel() { if (state.status === "review") update({ status: "ready", context: state.context }); },
    async approve() {
      const { context, decision } = state;
      if (state.status !== "review" || !context || !decision) return;
      const repository = context.repositories.find((candidate) => candidate.id === decision.repositoryId);
      if (!repository) return;
      const operation = begin(); update({ status: "saving", context, decision });
      try {
        const response = await transport(path, { method: "POST", credentials: "same-origin", signal: operation.signal,
          headers: { "content-type": "application/json" }, body: JSON.stringify({ action: decision.action, confirmed: true,
            repositoryId: repository.id, expectedConnectionFingerprint: context.connectionFingerprint,
            expectedInstallationId: context.installationId, expectedGithubConnectedAt: context.githubConnectedAt,
            expectedRepositoryFullName: repository.fullName, expectedGithubRepositoryId: repository.githubRepoId }) });
        if (!current(operation)) return;
        if (response.status === 409) { update({ status: "stale", message: "The connection or repository changed. Reload the list and review again." }); return; }
        if (!response.ok) throw new Error("Change unavailable");
        acknowledgement.parse(await response.json());
        if (!current(operation)) return;
        const after = await read(operation.signal);
        if (!current(operation)) return;
        const afterRepository = after.available ? after.repositories.find((candidate) => candidate.id === repository.id) : undefined;
        if (!after.available || !afterRepository || after.connectionFingerprint !== context.connectionFingerprint ||
            after.databaseDisplay !== context.databaseDisplay || after.installationId !== context.installationId || after.githubConnectedAt !== context.githubConnectedAt ||
            afterRepository.fullName !== repository.fullName || afterRepository.githubRepoId !== repository.githubRepoId) {
          update({ status: "stale", message: "The connection or repository changed. Reload the list and review again." }); return;
        }
        const confirmed = after.bindings.some((binding) => binding.repositoryId === repository.id);
        if (confirmed !== (decision.action === "confirm")) throw new Error("Change not corroborated");
        update({ status: "ready", context: after, message: decision.action === "confirm" ? "Association confirmed by you." : "Association removed." });
      } catch { if (current(operation)) update({ status: "unavailable", message: uncertain }); }
    },
  };
}
