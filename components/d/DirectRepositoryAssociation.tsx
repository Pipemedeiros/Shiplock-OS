"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { createDirectRepositoryConfirmation, type DirectRepositoryConfirmationState } from "@/lib/connections/directRepositoryConfirmation";

type Actions = Pick<ReturnType<typeof createDirectRepositoryConfirmation>, "review" | "cancel" | "load" | "approve">;
const textStyle = { fontSize: 12, lineHeight: 1.7, color: "var(--d-muted)" };

/** Pure view also exercised with server rendering; context identifiers are
 * never interpolated into DOM attributes, URLs or customer security claims. */
export function DirectRepositoryAssociationView({ state, actions, disabled = false, copy: suppliedCopy }: {
  state: DirectRepositoryConfirmationState; actions: Actions; disabled?: boolean;
  copy?: { sectionLabel: string; heading: string; intro: string; currentLabel: string; unconfigured: string };
}) {
  const copy = suppliedCopy ?? { sectionLabel: "Database repository associations", heading: "Which repositories use this database?",
    intro: "Optional. Confirm only repositories that use this connected database. This records your confirmation, not proof of a deployment or a security check. Cross-layer analysis is not enabled by this step.",
    currentLabel: "Current database", unconfigured: "Connect GitHub and read-only Postgres access, then reload the list." };
  const busy = disabled || state.status === "loading" || state.status === "saving";
  const repository = state.context?.repositories.find((candidate) => candidate.id === state.decision?.repositoryId);
  return (
    <section aria-label={copy.sectionLabel} aria-busy={busy} style={{ marginTop: 20, borderTop: "1px solid var(--d-border)", paddingTop: 16 }}>
      <h4 style={{ margin: "0 0 8px", fontSize: 13 }}>{copy.heading}</h4>
      <p style={textStyle}>{copy.intro}</p>
      {state.context && <p style={{ ...textStyle, overflowWrap: "anywhere" }}>{copy.currentLabel}: <span className="dxd-mono">{state.context.databaseDisplay}</span></p>}
      <div role="status" aria-live="polite" style={textStyle}>
        {state.status === "loading" && "Loading repository associations…"}
        {state.status === "saving" && "Saving your decision and checking the current association…"}
        {state.status === "unconfigured" && copy.unconfigured}
        {state.message}
      </div>
      {state.status === "ready" && state.context && (
        state.context.repositories.length === 0 ? <p style={textStyle}>Select repositories in <a href="/onboarding">GitHub setup</a> first.</p> :
          <ul style={{ listStyle: "none", padding: 0, margin: "12px 0" }}>
            {state.context.repositories.map((candidate) => {
              const confirmed = state.context?.bindings.some((binding) => binding.repositoryId === candidate.id);
              return <li key={candidate.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap", marginBottom: 12 }}>
                <div style={{ minWidth: 0, ...textStyle }}>
                  <span className="dxd-mono" style={{ overflowWrap: "anywhere" }}>{candidate.fullName}</span>
                  <span style={{ display: "block" }}>{confirmed ? "Confirmed by you" : "Not confirmed"}</span>
                </div>
                <button type="button" className="dxd-btn dxd-btn-ghost" disabled={busy}
                  aria-label={`${confirmed ? "Review removal for" : "Review association for"} ${candidate.fullName}`}
                  onClick={() => actions.review(candidate.id, confirmed ? "remove" : "confirm")}>
                  {confirmed ? "Review removal" : "Review association"}
                </button>
              </li>;
            })}
          </ul>
      )}
      {state.status === "review" && repository && state.decision && (
        <div style={{ margin: "12px 0", ...textStyle }}>
          <p style={{ overflowWrap: "anywhere" }}>{state.decision.action === "confirm"
            ? `Confirm that ${repository.fullName} uses this connected database?`
            : `Remove your database association for ${repository.fullName}? This does not disconnect the database.`}</p>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button type="button" className="dxd-btn" disabled={busy} onClick={() => { void actions.approve(); }}>
              {state.decision.action === "confirm" ? "Confirm association" : "Remove association"}
            </button>
            <button type="button" className="dxd-btn dxd-btn-ghost" disabled={busy} onClick={actions.cancel}>Cancel</button>
          </div>
        </div>
      )}
      {state.status !== "review" && <button type="button" className="dxd-btn dxd-btn-ghost" disabled={busy} onClick={() => { void actions.load(); }}>Reload associations</button>}
    </section>
  );
}

export function DirectRepositoryAssociation({ disabled, onMutationBusyChange }: {
  disabled: boolean; onMutationBusyChange: (busy: boolean) => void;
}) {
  const [controller] = useState(() => createDirectRepositoryConfirmation());
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getServerSnapshot);
  useEffect(() => {
    if (disabled) controller.suspend();
    else void controller.load();
    return controller.suspend;
  }, [controller, disabled]);
  const actions: Actions = { ...controller, async approve() {
    if (controller.getSnapshot().status !== "review") return;
    onMutationBusyChange(true);
    try { await controller.approve(); }
    finally { onMutationBusyChange(false); }
  } };
  return <DirectRepositoryAssociationView state={state} actions={actions} disabled={disabled} />;
}
