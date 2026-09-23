"use client";

import { useState } from "react";
import { repairMessage, waitForRepair } from "@/lib/repairReceiptClient";

/** One click, one PR for a change the customer's own AI proposed (10B-3b).
 * ShipLock opens it only after this click and never merges it. */
export function AiFixButton({ taskId }: { taskId: string }) {
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function open() {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch(`/api/intelligence/tasks/${encodeURIComponent(taskId)}/fix`, { method: "POST" });
      const json = (await res.json().catch(() => ({}))) as { error?: string; receiptId?: string };
      if (!res.ok || !json.receiptId) {
        setMessage(json.error ?? "Could not queue the pull request. Try again.");
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
        Review the pull request on GitHub
      </a>
    );
  }
  return (
    <div style={{ marginTop: 6 }}>
      <button type="button" className="v3-btn v3-btn-sm v3-primary" disabled={busy} onClick={open}>
        {busy ? "Opening…" : "Open a pull request"}
      </button>
      {message ? <p className="v3-small" style={{ marginTop: 4 }}>{message}</p> : null}
    </div>
  );
}
