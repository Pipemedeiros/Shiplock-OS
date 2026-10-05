"use client";

// The customer's standing approval for their own AI (10B-2b): which host
// supplies intelligence, when ShipLock may ask it for work, and within what
// budgets. Proposals only. Approving here never authorizes a branch or PR;
// each one still needs its own click on the finding. ShipLock runs no model
// (Felipe, 2026-10-01), so the host is always the customer's own agent.

import { useEffect, useState } from "react";
import type { ConnectionApproval, ConnectionView } from "@/lib/intelligence/connection";
import type { ApiKeyStatus } from "@/lib/intelligence/credential";
import { AgentSetup } from "./AgentSetup";

type Draft = Omit<ConnectionApproval, "allowProposals"> & { allowProposals: boolean };
export const defaultDraft: Draft = { host: "claude-code", deepScan: "weekly", prScan: "every_pr",
  runTokenBudget: 50_000, monthlyTokenBudget: 1_000_000, allowProposals: false };

const HOSTS: [Draft["host"], string][] = [["claude-code", "Claude Code"], ["codex", "Codex"], ["chatgpt", "ChatGPT"]];
const PR_SCANS: [Draft["prScan"], string][] = [["every_pr", "Every PR"], ["every_2_days", "Every 2 days"], ["daily", "Daily"],
  ["off", "Off"]];
const label = <T extends string>(options: [T, string][], value: T) => options.find(([v]) => v === value)?.[1] ?? value;

const row = { display: "grid", gridTemplateColumns: "180px 1fr", gap: 12, alignItems: "center", marginBottom: 12, fontSize: 14 } as const;
const note = { fontSize: 13, color: "var(--muted)", margin: "0 0 12px", maxWidth: 700 } as const;

export function IntelligenceApprovalView({ connection, apiKey, draft, busy, error, onChange, onApprove, onRevoke, onRemoveKey }: {
  connection: ConnectionView; apiKey: ApiKeyStatus; draft: Draft; busy: boolean; error: string;
  onChange: (draft: Draft) => void; onApprove: () => void; onRevoke: () => void; onRemoveKey: () => void;
}) {
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => onChange({ ...draft, [key]: value });
  return (
    <div>
      <div className="v3-setting">
        <div>
          <b>
            {connection.state === "approved" ? `${label(HOSTS, connection.host)} is approved`
              : connection.state === "revoked" ? "Your approval was revoked"
              : connection.state === "retired" ? "API key mode was retired" : "No AI connected"}
          </b>
          <small>
            {connection.state === "approved"
              ? `Deep scan ${connection.deepScan === "weekly" ? "weekly" : "off"}. PR scans: ${label(PR_SCANS, connection.prScan)}. Up to ${connection.runTokenBudget.toLocaleString("en-US")} tokens a run. `
                + `${connection.monthReportedTokens.toLocaleString("en-US")} of ${connection.monthlyTokenBudget.toLocaleString("en-US")} tokens this month, as reported by your agent (not verified).`
                + (connection.monthReportedTokens >= connection.monthlyTokenBudget ? " New AI checks are paused until next month." : "")
              : connection.state === "retired"
                ? "ShipLock no longer runs AI on a stored key. Choose your agent below and approve it to keep AI checks on deep scans and pull requests."
                : "Checks that need no AI already run. Connect your AI to reason about attack paths on deep scans and pull requests."}
          </small>
        </div>
        <span className={`v3-tag ${connection.state === "approved" ? "ok" : ""}`}>
          {connection.state === "none" || connection.state === "retired" ? "not connected" : connection.state}
        </span>
      </div>

      <div style={{ marginTop: 16 }}>
        <label style={row}>Your AI
          <select value={draft.host} onChange={(e) => set("host", e.target.value as Draft["host"])}>
            {HOSTS.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
          </select>
        </label>
        <label style={row}>Weekly deep scan
          <select value={draft.deepScan} onChange={(e) => set("deepScan", e.target.value as Draft["deepScan"])}>
            <option value="weekly">On</option><option value="off">Off</option>
          </select>
        </label>
        <label style={row}>PR scans
          <select value={draft.prScan} onChange={(e) => set("prScan", e.target.value as Draft["prScan"])}>
            {PR_SCANS.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
          </select>
        </label>
        <label style={row}>Tokens per run
          <input type="number" min={1000} max={1_000_000} step={1000} value={draft.runTokenBudget}
            onChange={(e) => set("runTokenBudget", Number(e.target.value))} />
        </label>
        <label style={row}>Tokens per month
          <input type="number" min={1000} max={50_000_000} step={1000} value={draft.monthlyTokenBudget}
            onChange={(e) => set("monthlyTokenBudget", Number(e.target.value))} />
        </label>

        {apiKey.stored && (
          <div style={{ ...note, color: "var(--ink)", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span>An API key ending in {apiKey.hint} is still stored, encrypted, and is no longer used.</span>
            <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onRemoveKey} disabled={busy}>Remove key</button>
          </div>
        )}
        <p style={note}>
          Budgets are a limit we ask your agent to respect: your agent spends its own allowance, so we cannot enforce them.
        </p>
        <AgentSetup host={draft.host} />
        <label style={{ ...note, display: "flex", gap: 8, alignItems: "flex-start", color: "var(--ink)" }}>
          <input type="checkbox" checked={draft.allowProposals} onChange={(e) => set("allowProposals", e.target.checked)} />
          <span>Let my AI send findings and suggested fixes on this schedule. Every pull request still needs your click,
            and we never merge or deploy.</span>
        </label>

        {error && <p role="alert" style={{ ...note, color: "var(--crit)" }}>{error}</p>}
        <div style={{ display: "flex", gap: 8 }}>
          <button type="button" className="v3-btn v3-btn-sm v3-primary" onClick={onApprove}
            disabled={busy || !draft.allowProposals}>Approve</button>
          {connection.state === "approved" && (
            <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onRevoke} disabled={busy}>Revoke</button>
          )}
        </div>
      </div>
    </div>
  );
}

export function IntelligencePanel() {
  const [connection, setConnection] = useState<ConnectionView>({ state: "none" });
  const [apiKey, setApiKey] = useState<ApiKeyStatus>({ stored: false });
  const [draft, setDraft] = useState<Draft>(defaultDraft);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const adopt = (view: ConnectionView) => {
    setConnection(view);
    if (view.state === "approved" || view.state === "revoked") {
      setDraft({ host: view.host, deepScan: view.deepScan, prScan: view.prScan, runTokenBudget: view.runTokenBudget,
        monthlyTokenBudget: view.monthlyTokenBudget, allowProposals: false });
    }
  };

  useEffect(() => {
    fetch("/api/intelligence/connection").then((r) => (r.ok ? r.json() : null))
      .then((view) => { if (view) adopt(view); }).catch(() => {});
    fetch("/api/intelligence/credential").then((r) => (r.ok ? r.json() : null))
      .then((status) => { if (status) setApiKey(status); }).catch(() => {});
  }, []);

  async function send(method: "POST" | "DELETE") {
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/intelligence/connection", method === "POST"
        ? { method, headers: { "content-type": "application/json" }, body: JSON.stringify(draft) } : { method });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setError(data.error ?? "Could not save. Try again."); return; }
      if (method === "POST") adopt(data);
      else setConnection(connection.state === "approved" ? { ...connection, state: "revoked" } : connection);
    } catch { setError("Could not reach ShipLock. Try again."); }
    finally { setBusy(false); }
  }

  async function removeKey() {
    setBusy(true); setError("");
    try {
      const res = await fetch("/api/intelligence/credential", { method: "DELETE" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setError(data.error ?? "Could not remove the key. Try again."); return; }
      setApiKey({ stored: false });
    } catch { setError("Could not reach ShipLock. Try again."); }
    finally { setBusy(false); }
  }

  return <IntelligenceApprovalView connection={connection} apiKey={apiKey} draft={draft} busy={busy} error={error}
    onChange={setDraft} onApprove={() => send("POST")} onRevoke={() => send("DELETE")} onRemoveKey={removeKey} />;
}
