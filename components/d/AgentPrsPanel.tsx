"use client";

// Agent pull requests (103, Felipe 2026-10-15): per repository, the founder
// lets their own agent ask ShipLock for fix pull requests, after reading the
// risks. Off by default; only this page turns it on (lib/agentPrs.ts).

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { AGENT_PRS_ACK, AGENT_PRS_RISKS } from "@/lib/agentPrs";

type Repo = { id: string; fullName: string; since: string | null };
const note = { fontSize: 13, color: "var(--muted)", margin: "0 0 10px", maxWidth: 700 } as const;
const day = (iso: string) => new Date(iso).toLocaleDateString("en", { month: "short", day: "numeric", year: "numeric" });

export function AgentPrsView({ repositories, open, accepted, busy, error, onOpen, onAccept, onGrant, onRevoke }: {
  repositories: Repo[]; open: string | null; accepted: boolean; busy: boolean; error: string;
  onOpen: (id: string | null) => void; onAccept: (v: boolean) => void; onGrant: (id: string) => void; onRevoke: (id: string) => void;
}) {
  return (
    <div>
      <p style={note}>
        Let your agent open the fix pull requests ShipLock offers, without a click from you each time. Your agent asks
        through ShipLock&apos;s MCP tools; ShipLock opens the pull request on a new branch and never merges.
      </p>
      {repositories.length === 0 ? <p style={note}>Select a repository first.</p> : null}
      {repositories.map((repo) => (
        <div key={repo.id} className="v3-setting" style={{ gridTemplateColumns: "1fr" }}>
          <div className="v3-row" style={{ justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
            <div>
              <b>{repo.fullName}</b>
              <small>{repo.since ? `On since ${day(repo.since)}` : "Off. Every pull request needs your click."}</small>
            </div>
            {repo.since ? (
              <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy} onClick={() => onRevoke(repo.id)}>Turn off</button>
            ) : open !== repo.id ? (
              <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy} onClick={() => onOpen(repo.id)}>Turn on</button>
            ) : null}
          </div>
          {!repo.since && open === repo.id ? (
            <div style={{ marginTop: 12 }}>
              <b style={{ fontWeight: 500, fontSize: 14 }}>Before you turn this on</b>
              <ul style={{ ...note, paddingLeft: 18, marginTop: 6 }}>
                {AGENT_PRS_RISKS.map((risk) => <li key={risk} style={{ marginBottom: 4 }}>{risk}</li>)}
              </ul>
              <label style={{ ...note, display: "flex", gap: 8, alignItems: "flex-start", color: "var(--ink)" }}>
                <input type="checkbox" checked={accepted} onChange={(e) => onAccept(e.target.checked)} />
                <span>I understand these risks and want my agent to open fix pull requests for {repo.fullName}.</span>
              </label>
              <div className="v3-row" style={{ gap: 8 }}>
                <button type="button" className="v3-btn v3-btn-sm v3-primary" disabled={busy || !accepted} onClick={() => onGrant(repo.id)}>
                  {busy ? <><Loader2 size={14} className="v3-spin" aria-hidden="true" /> Saving</> : "Let my agent open pull requests"}
                </button>
                <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy} onClick={() => onOpen(null)}>Cancel</button>
              </div>
            </div>
          ) : null}
        </div>
      ))}
      {error ? <p role="alert" style={{ ...note, color: "var(--crit)" }}>{error}</p> : null}
    </div>
  );
}

export function AgentPrsPanel({ repositories }: { repositories: Repo[] }) {
  const router = useRouter();
  const [open, setOpen] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const send = async (method: "POST" | "DELETE", repositoryId: string) => {
    setBusy(true);
    setError("");
    try {
      const res = await fetch("/api/intelligence/agent-prs", {
        method, headers: { "Content-Type": "application/json" },
        body: JSON.stringify(method === "POST" ? { repositoryId, acknowledgement: AGENT_PRS_ACK } : { repositoryId }),
      });
      const json = (await res.json().catch(() => ({}))) as { error?: string };
      if (!res.ok) throw new Error(json.error ?? "Try again in a moment.");
      setOpen(null);
      setAccepted(false);
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Try again in a moment.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AgentPrsView repositories={repositories} open={open} accepted={accepted} busy={busy} error={error}
      onOpen={(id) => { setOpen(id); setAccepted(false); }} onAccept={setAccepted}
      onGrant={(id) => send("POST", id)} onRevoke={(id) => send("DELETE", id)} />
  );
}
