"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { Loader2 } from "lucide-react";
import { startAndWaitForAudit } from "./auditClient";

/**
 * Runs an audit now.
 *
 * The button owns its own pending state rather than a global spinner, because
 * an audit takes minutes and the rest of the page stays usable while it runs.
 * On success the route is refreshed, so the server components re-read the new
 * findings instead of the client holding a second copy of them.
 */
export function RunAuditButton({ repository }: { repository: string }) {
  const router = useRouter();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <div style={{ textAlign: "right" }}>
      <button
        className="v3-btn v3-btn-sm v3-primary"
        disabled={running}
        onClick={async () => {
          setRunning(true);
          setError(null);
          try {
            await startAndWaitForAudit(repository);
            router.refresh();
          } catch (err) {
            setError(err instanceof Error ? err.message : "Something went wrong.");
          } finally {
            setRunning(false);
          }
        }}
      >
        {running ? <><Loader2 size={14} className="v3-spin" /> Auditing…</> : "Run an audit"}
      </button>
      {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)", marginTop: 6 }}>{error}</p> : null}
    </div>
  );
}
