/**
 * Live audit progress (Felipe 2026-10-06: the customer must SEE the audit
 * working, not wait on a spinner). Each step hands over the trace so far; one
 * write runs at a time, a write queued behind a slow one is replaced by the
 * newest trace, and a failed write is dropped. Progress never fails or holds
 * up the audit, and the final, fenced write of the run still decides what is
 * stored.
 */
export interface ProgressStep { time: string; label: string; note?: string; found?: boolean }

export function auditProgress(write: (trace: ProgressStep[]) => Promise<void>) {
  let running: Promise<void> = Promise.resolve();
  let pending: ProgressStep[] | null = null;
  let busy = false;

  const drain = async () => {
    busy = true;
    while (pending) {
      const next = pending;
      pending = null;
      try { await write(next); } catch { /* progress is best effort */ }
    }
    busy = false;
  };

  return {
    wrote(trace: readonly ProgressStep[]) {
      pending = trace.map((s) => ({ ...s }));
      if (!busy) running = drain();
    },
    flush(): Promise<void> {
      return running;
    },
  };
}
