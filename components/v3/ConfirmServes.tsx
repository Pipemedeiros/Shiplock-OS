"use client";

// Coverage's Live site fold asks once, in place, which repository a saved
// address serves, so live facts can join that repository's findings.
// It is the founder's confirmation, the same one Settings records through
// /api/app-url; nothing is bound without this click.

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

export function ConfirmServesView({ url, repositories, busy, error, onConfirm }: {
  url: string; repositories: string[]; busy: boolean; error: string; onConfirm: (repository: string) => void;
}) {
  const [serves, setServes] = useState(repositories[0] ?? "");
  const pending = busy ? <><Loader2 size={14} className="v3-spin" aria-hidden="true" /> Saving</> : null;
  return (
    <div className="v3-small">
      <p style={{ marginBottom: 10 }}>
        ShipLock reads <strong>{url}</strong> but does not know which repository it serves, so its findings and your live site
        are not joined. Confirm it and each issue says when your live site names its route.
      </p>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {repositories.length > 1 ? (
          <>
            <label htmlFor="confirm-serves">Serves</label>
            <select id="confirm-serves" value={serves} onChange={(e) => setServes(e.target.value)}>
              {repositories.map((r) => <option key={r} value={r}>{r}</option>)}
            </select>
          </>
        ) : null}
        <button type="button" className="v3-btn v3-btn-sm v3-primary" disabled={busy || !serves} aria-busy={busy || undefined}
          onClick={() => onConfirm(serves)}>{pending ?? (repositories.length > 1 ? "Confirm" : `It serves ${serves}`)}</button>
      </div>
      {error ? <p role="alert" style={{ color: "var(--crit)", marginTop: 8 }}>{error}</p> : null}
    </div>
  );
}

export function ConfirmServes({ url, repositories }: { url: string; repositories: string[] }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const confirm = async (repository: string) => {
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/app-url", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, repository }) });
      const json = (await res.json()) as { error?: string };
      if (!res.ok) throw new Error(json.error ?? "Could not save. Try again.");
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save. Try again.");
    } finally {
      setBusy(false);
    }
  };
  return <ConfirmServesView url={url} repositories={repositories} busy={busy} error={error} onConfirm={(r) => void confirm(r)} />;
}
