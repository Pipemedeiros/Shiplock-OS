"use client";

import { useState } from "react";
import { repairMessage, waitForRepair } from "@/lib/repairReceiptClient";
import { RepairPreviewPanel } from "./RepairPreview";

/** One click, one fix PR into this pull request's branch. ShipLock
 * opens it only after this click and never merges it. */
export function PullRequestFixButton({ reviewId, findingId }: { reviewId: string; findingId: string }) {
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function requestFix() {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch("/api/fix/pull-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ reviewId, findingId }),
      });
      const json = (await res.json().catch(() => ({}))) as { error?: string; receiptId?: string };
      if (!res.ok || !json.receiptId) {
        setMessage(json.error ?? "Could not queue the fix. Try again.");
        return;
      }
      const view = await waitForRepair(json.receiptId);
      if (view.status === "opened" && view.url) setUrl(view.url);
      else setMessage(repairMessage(view));
    } catch {
      setMessage("Could not reach ShipLock. Try again.");
    } finally {
      setBusy(false);
    }
  }

  if (url) {
    return (
      <a href={url} target="_blank" rel="noreferrer" className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 6 }}>
        Review the fix request on GitHub
      </a>
    );
  }
  return (
    <div style={{ marginTop: 6 }}>
      {/* See exactly what the fix before merge would write, then click. */}
      <RepairPreviewPanel body={{ lane: "pull-request", reviewId, findingId }} busy={busy} onOpen={requestFix} />
      {message ? <p role="status" className="v3-small" style={{ marginTop: 4 }}>{message}</p> : null}
    </div>
  );
}
