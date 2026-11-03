"use client";

import { useState } from "react";
import { repairMessage, waitForRepair } from "@/lib/repairReceiptClient";
import type { HotRouteOffer } from "@/lib/traffic/hotRoutes";
import { RepairPreviewPanel } from "./RepairPreview";

/** One click, one rate-limit PR for a route observed traffic reached.
 * The PR adds one helper file that stays off until the customer turns it on;
 * ShipLock never merges. */
function RateLimitButton({ repositoryId, routeFile }: { repositoryId: string; routeFile: string }) {
  const [busy, setBusy] = useState(false);
  const [url, setUrl] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function request() {
    setBusy(true);
    setMessage(null);
    try {
      const res = await fetch("/api/fix/rate-limit", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repositoryId, routeFile }),
      });
      const json = (await res.json().catch(() => ({}))) as { error?: string; receiptId?: string };
      if (!res.ok || !json.receiptId) { setMessage(json.error ?? "Could not queue the pull request. Try again."); return; }
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
    return <a href={url} target="_blank" rel="noreferrer" className="v3-btn v3-btn-sm v3-ghost">Review it on GitHub</a>;
  }
  return (
    <span>
      <RepairPreviewPanel body={{ action: "rate-limit-pr", repositoryId, findingId: `traffic:${routeFile}` }} busy={busy} onOpen={request} />
      {message ? <span role="status" className="v3-small" style={{ marginLeft: 8 }}>{message}</span> : null}
    </span>
  );
}

export function RateLimitOffers({ repositoryId, offers }: { repositoryId: string; offers: HotRouteOffer[] }) {
  if (offers.length === 0) return null;
  return (
    <div style={{ marginTop: 6 }}>
      <p className="v3-small" style={{ margin: "0 0 4px" }}>
        Suggested: a pull request that adds one rate-limit helper, off until you turn it on. It changes no existing file.
      </p>
      {offers.map((offer) => (
        <div key={offer.file} className="v3-between" style={{ fontSize: 13, padding: "3px 0" }}>
          <span>{offer.pattern}: {offer.suspiciousRequests} suspicious requests</span>
          <RateLimitButton repositoryId={repositoryId} routeFile={offer.file} />
        </div>
      ))}
    </div>
  );
}
