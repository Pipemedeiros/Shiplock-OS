interface AuditTraceStep { time: string; label: string; note?: string; found?: boolean }
export interface AuditRunState {
  status: "queued" | "running" | "complete" | "failed";
  trace: AuditTraceStep[];
  findings_count: number;
  entries_found: number | null;
  error?: string | null;
}

const wait = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds));

/** Start once, then follow the durable run rather than holding the POST open. */
export async function startAndWaitForAudit(
  repository: string,
  onProgress?: (run: AuditRunState) => void,
): Promise<AuditRunState> {
  const response = await fetch("/api/audit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repository, requestId: crypto.randomUUID() }),
  });
  const receipt = (await response.json()) as { runId?: string; error?: string };
  if (!response.ok || !receipt.runId) throw new Error(receipt.error ?? "The audit could not be queued.");

  let last: AuditRunState["status"] = "queued";
  for (let attempt = 0; attempt < 90; attempt++) {
    const read = await fetch(`/api/audit/${encodeURIComponent(receipt.runId)}`, { cache: "no-store" });
    const run = (await read.json()) as AuditRunState & { error?: string };
    if (!read.ok) throw new Error(run.error ?? "The audit status could not be read.");
    onProgress?.(run);
    last = run.status;
    if (run.status === "complete") return run;
    if (run.status === "failed") throw new Error("The audit stopped before it finished.");
    await wait(1_000);
  }
  throw new Error(last === "running"
    ? "The audit is still running and finishes on its own. Activity shows it when it is done."
    : "The audit is still queued. You can leave this page and return to the run later.");
}
