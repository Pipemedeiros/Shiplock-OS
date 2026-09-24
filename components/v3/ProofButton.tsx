"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { FlaskConical } from "lucide-react";
import type { ProofView } from "@/lib/proving/proofStatus";

/**
 * One clicked test of one finding's table (Q7 / Step 6A-3). The click issues
 * a per-test authorization (Q5) and queues it (/api/proving/run); the worker
 * rebuilds the table and its policies on ShipLock's own disposable database
 * with synthetic users and records one outcome. "Ran" is one probe on a copy,
 * never a statement that the table is protected.
 */
export const REASON_TEXT: Record<string, string> = {
  kill_switch: "monitoring only is on for this account",
  not_enabled: "testing is not turned on for this account",
  repository_unselected: "this repository is no longer selected",
  finding_mismatch: "this finding changed or was closed",
  unsupported_schema: "only tables in the public schema can be tested",
  database_unread: "no current read of your database policies is linked to this repository",
  columns_unread: "your table's columns have not been read yet",
  no_owner_column: "we could not tell which column names the owner of a row",
  no_policies: "no policies were read for this table",
  not_replicable: "a policy depends on something we cannot rebuild faithfully",
  control_failed: "the copy did not behave like your table, so a result would mean nothing",
  replica_unavailable: "the disposable copy could not start",
  replica_error: "the disposable copy could not run the test",
  statement_budget: "it reached its query budget",
  time_limit: "it ran past its time limit",
  resource_limit: "it reached its memory limit",
};
const reasonText = (reason: string | null) => (reason && REASON_TEXT[reason]) || "the test could not finish";

function Outcome({ view }: { view: ProofView }) {
  if (view.state === "pending") return <p className="v3-small">Testing on a disposable copy. The result appears here when it finishes.</p>;
  if (view.state === "failed") return <p className="v3-small">Stopped: the test could not finish.</p>;
  if (view.outcome === "reproduced") {
    return (
      <p className="v3-small">
        <span className="v3-tag crit">Reproduced on a disposable copy</span>{" "}
        A synthetic user read another synthetic user&apos;s row through these policies.
      </p>
    );
  }
  if (view.outcome === "ran") {
    return (
      <p className="v3-small">
        <span className="v3-tag">Test ran, not reproduced</span>{" "}
        One probe on a rebuilt copy of this table. It does not show the table is protected.
      </p>
    );
  }
  if (view.outcome === "aborted") return <p className="v3-small">Stopped: {reasonText(view.reason)}.</p>;
  return <p className="v3-small">Could not test: {reasonText(view.reason)}.</p>;
}

export function ProofPanel({ repositoryId, findingId, table, view }: {
  repositoryId: string; findingId: string; table: string; view: ProofView | null;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const pending = busy || view?.state === "pending";

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const authorize = await fetch("/api/proving/authorize", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repositoryId, findingId, table, key: crypto.randomUUID() }),
      });
      const issued = (await authorize.json()) as { authorizationId?: string; error?: string };
      if (!authorize.ok || !issued.authorizationId) throw new Error(issued.error ?? "Could not start the test.");
      const run = await fetch("/api/proving/run", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ authorizationId: issued.authorizationId }),
      });
      const queued = (await run.json()) as { error?: string };
      if (!run.ok) throw new Error(queued.error ?? "Could not start the test.");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the test.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="v3-stack" style={{ gap: 8 }}>
      <p className="v3-small">
        Rebuilds {table} and its policies on ShipLock&apos;s own disposable database with two synthetic users and
        checks whether one can read the other&apos;s row. It never touches your database.
      </p>
      {view ? <Outcome view={view} /> : null}
      <button className="v3-btn v3-btn-sm v3-ghost" style={{ alignSelf: "flex-start" }} disabled={pending} onClick={start}>
        <FlaskConical size={14} /> {pending ? "Testing" : view ? "Test again" : "Test on a disposable copy"}
      </button>
      {error ? <p className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
    </div>
  );
}
