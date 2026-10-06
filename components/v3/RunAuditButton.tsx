"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Loader2 } from "lucide-react";
import { startAndWaitForAudit, type AuditRunState } from "./auditClient";

/**
 * Runs an audit now.
 *
 * The button owns its own pending state rather than a global spinner, because
 * an audit takes minutes and the rest of the page stays usable while it runs.
 * On success the route is refreshed, so the server components re-read the new
 * findings instead of the client holding a second copy of them.
 */
export function RunAuditButton({ repository, secondary = false }: { repository: string; secondary?: boolean }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [run, setRun] = useState<AuditRunState | null>(null);

  return (
    <div style={{ textAlign: "right" }}>
      <button
        className={`v3-btn v3-btn-sm ${secondary ? "v3-ondark" : "v3-primary"}`}
        disabled={running}
        onClick={async () => {
          setRunning(true);
          setError(null);
          setRun(null);
          try {
            await startAndWaitForAudit(repository, setRun);
            router.refresh();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Something went wrong.");
          } finally {
            setRunning(false);
            setRun(null);
          }
        }}
      >
        {running ? <><Loader2 size={14} className="v3-spin" /> Auditing…</> : "Run an audit"}
      </button>
      {running ? <AuditProgressLine run={run} /> : null}
      {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)", marginTop: 6 }}>{error}</p> : null}
    </div>
  );
}

/** The step a running audit is on, as one status message read aloud once
 * per change. The trace is the audit's own record, saved as it runs. */
export function AuditProgressLine({ run }: { run: AuditRunState | null }) {
  if (!run) return null;
  const last = run.trace[run.trace.length - 1];
  const text = run.status === "queued" ? "Queued. Waiting for a worker to pick it up."
    : last ? `Step ${run.trace.length}. ${last.label}` : "Starting the read-only checkout.";
  return (
    <p role="status" aria-atomic="true" className="v3-small" style={{ marginTop: 6, maxWidth: 320, marginLeft: "auto" }}>
      {text}
    </p>
  );
}
