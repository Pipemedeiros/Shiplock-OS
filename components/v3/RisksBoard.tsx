"use client";

import { useMemo, useState } from "react";
import { RepairPreviewPanel } from "./RepairPreview";
import { useRouter } from "next/navigation";
import { GitPullRequest, ShieldCheck, Wrench } from "lucide-react";
import type { Severity } from "@/lib/types";
import type { Confidence, FixKind } from "@/lib/agent/findings";
import type { DashboardFinding } from "@/lib/agent/dashboardData";
import { Chain, Claims, Conf, Sev } from "./FindingParts";
import { repairMessage, waitForRepair } from "@/lib/repairReceiptClient";
import type { ProofOffer } from "@/lib/proving/proofStatus";
import { ProofPanel } from "./ProofButton";
import { AgentHandoff } from "./AgentHandoff";

/**
 * The list and the inspector, side by side.
 *
 * A drawer would cover the list, and comparing two findings is the main thing
 * anyone does here. The inspector stays pinned while the list scrolls.
 */

type Tab = "why" | "fix";

const FIX_NOTE: Record<FixKind, string> = {
  pr: "Opened on its own branch for you to review and merge. We never push to your default branch.",
  one_click: "Small, additive and reversible. The previous state is stored before anything changes.",
  manual: "This is a decision about your architecture, not a mechanical change. The call is yours.",
};

export function RisksBoard({ findings, proofs = {} }: { findings: DashboardFinding[]; proofs?: Record<string, ProofOffer> }) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [confidence, setConfidence] = useState<Confidence | "all">("all");
  const [selectedId, setSelectedId] = useState<string>(findings[0]?.rowId ?? "");

  const visible = useMemo(
    () =>
      findings.filter(
        (f) =>
          (severity === "all" || f.severity === severity) &&
          (confidence === "all" || f.confidence === confidence),
      ),
    [findings, severity, confidence],
  );

  const selected = visible.find((f) => f.rowId === selectedId) ?? visible[0];

  if (findings.length === 0) {
    return (
      <div className="v3-empty">
        <p>Nothing open.</p>
        <p className="v3-small" style={{ marginTop: 6 }}>
          Run an audit, or check Coverage for what the last one could not reach.
        </p>
      </div>
    );
  }

  return (
    <>
      <div className="v3-filters">
        <div className="v3-filter">
          <span>Severity</span>
          {(["all", "CRITICAL", "WARNING", "INFO"] as const).map((s) => (
            <button key={s} className={severity === s ? "on" : ""} onClick={() => setSeverity(s)}>
              {s === "all" ? "all" : s.toLowerCase()}
            </button>
          ))}
        </div>
        <div className="v3-filter">
          <span>Confidence</span>
          {(["all", "proven", "corroborated", "inferred"] as const).map((c) => (
            <button key={c} className={confidence === c ? "on" : ""} onClick={() => setConfidence(c)}>
              {c}
            </button>
          ))}
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="v3-empty">
          <p>Nothing matches those filters.</p>
        </div>
      ) : (
        <div className="v3-risks">
          <div className="v3-risk-list">
            {visible.map((f) => (
              <button
                key={f.rowId}
                className={`v3-risk${selected?.rowId === f.rowId ? " on" : ""}`}
                onClick={() => setSelectedId(f.rowId)}
                aria-current={selected?.rowId === f.rowId}
              >
                <div className="v3-row">
                  <Sev severity={f.severity} />
                  <Conf confidence={f.confidence} />
                  {f.fixPrUrl ? <span className="v3-tag ok">PR #{f.fixPrNumber}</span> : null}
                </div>
                <h2>{f.title}</h2>
                <p>{f.consequence}</p>
                <p className="v3-small">{f.entry ?? f.file ?? f.repository ?? ""}</p>
              </button>
            ))}
          </div>

          {selected ? <Inspector finding={selected} proof={proofs[selected.rowId] ?? null} /> : null}
        </div>
      )}
    </>
  );
}

function Inspector({ finding, proof }: { finding: DashboardFinding; proof: ProofOffer | null }) {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("why");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const FixIcon = finding.fixKind === "pr" ? GitPullRequest : finding.fixKind === "one_click" ? ShieldCheck : Wrench;

  return (
    <aside className="v3-inspector">
      <div className="v3-card-p">
        <div className="v3-row">
          <Sev severity={finding.severity} />
          <Conf confidence={finding.confidence} />
        </div>
        <h2 className="v3-serif" style={{ fontSize: 21, margin: "12px 0 8px" }}>{finding.title}</h2>
        <p className="v3-sub" style={{ fontSize: 14 }}>{finding.consequence}</p>
        {finding.entry ? (
          <Chain entry={finding.entry} file={finding.file} blastRadius={finding.blastRadius} />
        ) : null}
      </div>

      <div className="v3-tabs">
        {([["why", "Evidence"], ["fix", "Fix"]] as const).map(([k, label]) => (
          <button key={k} className={tab === k ? "on" : ""} onClick={() => setTab(k)}>{label}</button>
        ))}
      </div>

      <div className="v3-card-p">
        {tab === "why" ? <Claims claims={finding.claims} /> : null}
        {tab === "why" && proof ? (
          <div style={{ marginTop: 16 }}>
            <ProofPanel key={finding.rowId} repositoryId={proof.repositoryId} findingId={proof.findingId} table={proof.table} view={proof.view} />
          </div>
        ) : null}

        {tab === "fix" ? (
          <div className="v3-stack" style={{ gap: 16 }}>
            <div>
              <div className="v3-row" style={{ marginBottom: 8 }}>
                <FixIcon size={15} />
                <b style={{ fontWeight: 500 }}>
                  {finding.fixKind === "manual" ? "Your call" : "A fix can be opened for this"}
                </b>
              </div>
              <p className="v3-small">{FIX_NOTE[finding.fixKind]}</p>
            </div>

            {finding.fixPrUrl ? (
              <a href={finding.fixPrUrl} target="_blank" rel="noreferrer" className="v3-btn v3-btn-sm v3-ghost" style={{ alignSelf: "flex-start" }}>
                Review pull request #{finding.fixPrNumber}
              </a>
            ) : finding.fixKind === "pr" ? (
              // Q13: preview exactly what the pull request would write, then click.
              <RepairPreviewPanel
                key={finding.id}
                body={{ lane: "risk", findingId: finding.id }}
                busy={busy}
                onOpen={async () => {
                  setBusy(true);
                  setError(null);
                  try {
                    const res = await fetch("/api/fix/pr", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ findingId: finding.id }),
                    });
                    const json = (await res.json()) as { error?: string; receiptId?: string };
                    if (!res.ok) throw new Error(json.error ?? "Could not open the pull request.");
                    // The click is queued as a receipted repair (3F-C2d); follow it
                    // until GitHub confirms the PR, then show it on the finding.
                    if (json.receiptId) {
                      const view = await waitForRepair(json.receiptId);
                      if (view.status !== "opened") setError(repairMessage(view));
                    }
                    router.refresh();
                  } catch (err) {
                    setError(err instanceof Error ? err.message : "Something went wrong.");
                  } finally {
                    setBusy(false);
                  }
                }}
              />
            ) : null}

            {!finding.fixPrUrl ? (
              <AgentHandoff finding={{ id: finding.id, title: finding.title, repository: finding.repository, fixKind: finding.fixKind }} />
            ) : null}

            {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
          </div>
        ) : null}
      </div>
    </aside>
  );
}
