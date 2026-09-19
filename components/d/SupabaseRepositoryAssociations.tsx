"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { DirectRepositoryAssociationView } from "./DirectRepositoryAssociation";
import { createSupabaseRepositoryConfirmation, type SupabaseBindingCollector,
  type SupabaseRepositoryConfirmationState } from "@/lib/connections/supabaseRepositoryConfirmation";
import type { DirectRepositoryConfirmationState } from "@/lib/connections/directRepositoryConfirmation";

type Controller = ReturnType<typeof createSupabaseRepositoryConfirmation>;
type Actions = Pick<Controller, "review" | "cancel" | "load" | "approve">;
const labels = {
  "supabase-management": { heading: "Management API access", intro: "Optional. Confirm repositories that use the project connected through read-only Management API access. This records your confirmation, not proof of a deployment or a security check. Cross-layer analysis is not enabled by this step.",
    unconfigured: "This Management API access path is not connected." },
  "supabase-scan": { heading: "Endpoint scan access", intro: "Optional. Confirm repositories that use the project configured for endpoint scans. This decision is separate from Management API access and is not proof of a deployment or a security check. Cross-layer analysis is not enabled by this step.",
    unconfigured: "This endpoint scan access path is not configured." },
} as const;

export function SupabaseRepositoryAssociationView({ collector, state, actions, disabled }: {
  collector: SupabaseBindingCollector; state: SupabaseRepositoryConfirmationState; actions: Actions; disabled: boolean;
}) {
  const context = state.context;
  const adapted = { ...state, ...(context ? { context: { ...context,
    databaseDisplay: context.endpointUrl ?? context.projectRef } } : {}) } as DirectRepositoryConfirmationState;
  const label = labels[collector];
  return <DirectRepositoryAssociationView state={adapted} actions={actions} disabled={disabled} copy={{
    sectionLabel: `${label.heading} repository associations`, heading: label.heading, intro: label.intro,
    currentLabel: "Current Supabase project", unconfigured: label.unconfigured,
  }} />;
}

function Association({ collector, disabled, beginMutation, endMutation }: {
  collector: SupabaseBindingCollector; disabled: boolean; beginMutation: (collector: SupabaseBindingCollector) => boolean; endMutation: () => void;
}) {
  const [controller] = useState(() => createSupabaseRepositoryConfirmation(collector));
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getServerSnapshot);
  useEffect(() => {
    if (disabled) controller.suspend(); else void controller.load();
    return controller.suspend;
  }, [controller, disabled]);
  const actions: Actions = { ...controller, async approve() {
    if (controller.getSnapshot().status !== "review" || !beginMutation(collector)) return;
    try { await controller.approve(); } finally { endMutation(); }
  } };
  return <SupabaseRepositoryAssociationView collector={collector} state={state} actions={actions} disabled={disabled} />;
}

export function SupabaseRepositoryAssociations({ disabled, onMutationBusyChange }: {
  disabled: boolean; onMutationBusyChange: (busy: boolean) => void;
}) {
  const lock = useRef(false); const [active, setActive] = useState<SupabaseBindingCollector | null>(null);
  const beginMutation = (collector: SupabaseBindingCollector) => {
    if (lock.current) return false;
    lock.current = true; setActive(collector); onMutationBusyChange(true); return true;
  };
  const endMutation = () => { lock.current = false; setActive(null); onMutationBusyChange(false); };
  return <div role="group" aria-label="Supabase repository associations">
    {(["supabase-management", "supabase-scan"] as const).map((collector) =>
      <Association key={collector} collector={collector} disabled={disabled || (active !== null && active !== collector)}
        beginMutation={beginMutation} endMutation={endMutation} />)}
  </div>;
}
