"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { CONNECTION_CATEGORIES } from "@/lib/connections/categories";
import { useRouter } from "next/navigation";
import { ArrowRight, Check, GitPullRequest, LockKeyhole, ShieldCheck } from "lucide-react";
import { startAndWaitForAudit } from "./auditClient";

/**
 * Onboarding: connect GitHub, choose repositories, see the stack we read, run
 * the first audit.
 *
 * GitHub is the only required connection and the audit produces real findings
 * with nothing else. The stack step exists because reading a repository tells
 * us what a customer runs, and showing that back is both the proof we read
 * their code and the specific, non-generic place to offer a deeper connection.
 *
 * Every offer on the stack step is skippable, and a category with no connector
 * behind it says so rather than rendering a button that opens nothing. Asking
 * for six credentials before showing a single finding is how a security tool
 * gets abandoned in the first two minutes.
 */

interface Repo {
  fullName: string;
  defaultBranch: string;
  isPrivate: boolean | null;
  selected: boolean;
  lastAuditAt: string | null;
}

interface TraceStep {
  time: string;
  label: string;
  note?: string;
  found?: boolean;
}

export interface DetectedTool {
  id: string;
  name: string;
  kind: string;
  evidence: string;
}

interface RouteAnalysisSupport {
  level: "deep" | "inventory_only";
  framework: "nextjs" | "unsupported_or_unknown";
  reason: string;
}

type Step = "connect" | "repos" | "stack" | "audit";

export function OnboardingFlow({
  connected,
  initialRepos,
  listError,
}: {
  connected: boolean;
  initialRepos: Repo[];
  listError: string | null;
}) {
  const router = useRouter();
  const [step, setStep] = useState<Step>(connected ? "repos" : "connect");
  const [repos, setRepos] = useState<Repo[]>(initialRepos);
  // Preselect what was already chosen; otherwise nothing. We do not guess which
  // repository matters -- getting that wrong wastes the first audit.
  const [picked, setPicked] = useState<string[]>(
    initialRepos.filter((r) => r.selected).map((r) => r.fullName),
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(listError);

  // The list is rendered from the server on first paint. This only re-reads it
  // when the customer asks, after changing which repositories the installation
  // can see on GitHub's side.
  const loadRepos = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/repos");
      const json = (await res.json()) as { repositories?: Repo[]; error?: string };
      if (!res.ok) throw new Error(json.error ?? "Could not read your repositories.");
      setRepos(json.repositories ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }, []);

  return (
    <div className="v3-narrow" style={{ padding: "52px 0 90px" }}>
      <Stepper step={step} />

      {step === "connect" ? <Connect /> : null}

      {step === "repos" ? (
        <RepoPicker
          repos={repos}
          picked={picked}
          loading={loading}
          error={error}
          onReload={loadRepos}
          onToggle={(name) =>
            setPicked((p) => (p.includes(name) ? p.filter((x) => x !== name) : [...p, name]))
          }
          onContinue={async () => {
            setLoading(true);
            setError(null);
            try {
              const res = await fetch("/api/repos", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ repositories: picked }),
              });
              if (!res.ok) throw new Error("Could not save your selection.");
              setStep("stack");
            } catch (err) {
              setError(err instanceof Error ? err.message : "Something went wrong.");
            } finally {
              setLoading(false);
            }
          }}
        />
      ) : null}

      {step === "stack" ? (
        <StackStep repository={picked[0]} onContinue={() => setStep("audit")} />
      ) : null}

      {step === "audit" ? (
        <FirstAudit repository={picked[0]} onDone={() => router.push("/dashboard")} />
      ) : null}
    </div>
  );
}

function Stepper({ step }: { step: Step }) {
  const labels: [Step, string][] = [
    ["connect", "Connect GitHub"],
    ["repos", "Choose repositories"],
    ["stack", "Your stack"],
    ["audit", "First audit"],
  ];
  const index = labels.findIndex(([s]) => s === step);

  return (
    <div className="v3-steps" style={{ marginBottom: 34 }}>
      {labels.map(([, label], i) => (
        <div key={label} className={i === index ? "on" : i < index ? "done" : ""}>
          <i>{i < index ? <Check size={11} /> : i + 1}</i>
          <span>{label}</span>
        </div>
      ))}
    </div>
  );
}

function Connect() {
  return (
    <div className="v3-stack">
      <div>
        <p className="v3-eyebrow">Setup</p>
        <h1 className="v3-serif" style={{ fontSize: 32, margin: "12px 0 10px" }}>Connect GitHub.</h1>
        <p className="v3-sub" style={{ maxWidth: 560 }}>
          Read-only collection on the repositories you pick. Write access is used only to prepare a
          new ShipLock fix branch and open a pull request for your review. We never write or merge
          your default branch.
        </p>
      </div>

      <div className="v3-card">
        <div className="v3-hd">
          <h2 className="v3-eyebrow">What we are asking for</h2>
          <span className="v3-tag ok">No default-branch writes</span>
        </div>
        <div className="v3-card-p">
          {[
            { Icon: LockKeyhole, name: "Repository contents", detail: "Read the code; write only a new fix branch", access: "read · write" },
            { Icon: GitPullRequest, name: "Pull requests", detail: "Open fix branches for you to merge", access: "read · write" },
            { Icon: ShieldCheck, name: "Checks", detail: "Report a verdict on a pull request before you merge it", access: "write" },
          ].map(({ Icon, name, detail, access }) => (
            <div className="v3-setting" key={name}>
              <div className="v3-row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}>
                <Icon size={17} style={{ marginTop: 2, color: "var(--muted)" }} />
                <span>
                  <b style={{ fontWeight: 500, fontSize: 14.5 }}>{name}</b>
                  <small style={{ display: "block", color: "var(--muted)", fontSize: 13 }}>{detail}</small>
                </span>
              </div>
              <span className="v3-mono v3-small">{access}</span>
            </div>
          ))}
          <p className="v3-small" style={{ marginTop: 16 }}>
            We never push to your default branch. Disconnecting stops future repository reads.
          </p>
          <a href="/api/deep/github/connect" className="v3-btn v3-primary" style={{ marginTop: 16 }}>
            Install the GitHub App <ArrowRight size={15} />
          </a>
        </div>
      </div>
    </div>
  );
}

function RepoPicker({
  repos, picked, loading, error, onToggle, onContinue, onReload,
}: {
  repos: Repo[];
  picked: string[];
  loading: boolean;
  error: string | null;
  onToggle: (name: string) => void;
  onContinue: () => void;
  onReload: () => void;
}) {
  return (
    <div className="v3-stack">
      <div>
        <p className="v3-eyebrow">Setup · repositories</p>
        <h1 className="v3-serif" style={{ fontSize: 30, margin: "12px 0 10px" }}>
          Which of these are in production?
        </h1>
        <p className="v3-sub">
          Start with the one that serves your users. Marketing sites and infrastructure repos are
          usually noise; you can add them later.
        </p>
      </div>

      {error ? <div className="v3-card v3-card-p" style={{ borderColor: "var(--crit)" }}>{error}</div> : null}

      {loading && repos.length === 0 ? (
        <div className="v3-empty">Reading your repositories…</div>
      ) : repos.length === 0 ? (
        <div className="v3-empty">
          <p>No repositories are visible to the installation.</p>
          <p className="v3-small" style={{ marginTop: 6 }}>
            Grant the app access to at least one repository on GitHub, then reload.
          </p>
          <button className="v3-btn v3-btn-sm v3-ghost" style={{ marginTop: 14 }} onClick={onReload}>
            Reload
          </button>
        </div>
      ) : (
        <div className="v3-stack" style={{ gap: 9 }}>
          {repos.map((r) => {
            const on = picked.includes(r.fullName);
            return (
              <button key={r.fullName} className={`v3-pick${on ? " on" : ""}`} aria-pressed={on} onClick={() => onToggle(r.fullName)}>
                <div className="v3-row" style={{ gap: 11, flexWrap: "nowrap" }}>
                  <span style={{ color: on ? "var(--bronze)" : "var(--muted-2)", display: "flex" }}>
                    {on ? <Check size={15} /> : <span style={{ width: 15 }} />}
                  </span>
                  <span>
                    <b className="v3-mono" style={{ fontSize: 13.5, fontWeight: 500 }}>{r.fullName}</b>
                    {r.isPrivate ? <span className="v3-tag" style={{ marginLeft: 8 }}>private</span> : null}
                    <small style={{ display: "block", color: "var(--muted)", fontSize: 12.5, marginTop: 2 }}>
                      {r.defaultBranch}
                      {r.lastAuditAt ? ` · last audited ${new Date(r.lastAuditAt).toLocaleDateString()}` : ""}
                    </small>
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      )}

      <div className="v3-row">
        <button className="v3-btn v3-primary" disabled={picked.length === 0 || loading} onClick={onContinue}>
          {loading ? "Saving…" : "Inventory selected repositories"}
        </button>
        <span className="v3-small">
          {picked.length} selected · the first selected repository is audited now
        </span>
        <button className="v3-btn v3-btn-sm v3-quiet" onClick={onReload} disabled={loading}>
          Reload list
        </button>
      </div>
    </div>
  );
}

/**
 * The first audit, watched live.
 *
 * The trace is the point. A customer who can read what we did, line by line,
 * can disagree with it; one who cannot is being asked to take a security claim
 * on faith.
 */

/**
 * What we read out of the repository, grouped by category, with an offer to
 * connect each one.
 *
 * The argument this screen has to make, in the order it makes it: we read your
 * code, here is what it runs, and here is the part of each service the code
 * cannot tell us.
 *
 * There is no connect action. The MVP reads code and infers (owner decision
 * 2026-08-31, connectors on the roadmap), so this screen states the boundary
 * instead of offering to cross it. Naming what we could not see is the same
 * argument the Coverage page makes, and it is worth more than a button we
 * cannot honour yet.
 */
/** Lowercases the first letter so a sentence can be embedded mid-clause. */
function lowerFirst(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1);
}

function StackStep({
  repository,
  onContinue,
}: {
  repository: string;
  onContinue: () => void;
}) {
  const [tools, setTools] = useState<DetectedTool[] | null>(null);
  const [authUnknown, setAuthUnknown] = useState(false);
  const [routeAnalysis, setRouteAnalysis] = useState<RouteAnalysisSupport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    (async () => {
      try {
        const res = await fetch("/api/stack/detect", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repository }),
        });
        const json = (await res.json()) as {
          tools?: DetectedTool[];
          authUnknown?: boolean;
          routeAnalysis?: RouteAnalysisSupport;
          error?: string;
        };
        if (!res.ok) throw new Error(json.error ?? "Could not read the repository.");
        setTools(json.tools ?? []);
        setAuthUnknown(Boolean(json.authUnknown));
        setRouteAnalysis(json.routeAnalysis ?? null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Something went wrong.");
      }
    })();
  }, [repository]);

  const groups = CONNECTION_CATEGORIES.map((category) => ({
    category,
    found: (tools ?? []).filter((t) => category.kinds.includes(t.kind as never)),
  })).filter((g) => g.found.length > 0);

  return (
    <div className="v3-stack">
      <div>
        <p className="v3-eyebrow">Your stack</p>
        <h1 className="v3-serif" style={{ fontSize: 32, margin: "12px 0 10px" }}>
          {tools === null ? "Reading your repository" : "This is what your code runs"}
        </h1>
        <p className="v3-sub" style={{ maxWidth: 580 }}>
          Read from your manifest, your imports and your schema. Nothing here was typed in.
          The audit runs on your repository, so what a provider has configured in its own
          dashboard stays outside it, and each card says what that leaves out.
        </p>
      </div>

      {error ? (
        <div className="v3-card v3-card-p" style={{ borderColor: "var(--crit)" }}>
          <p>{error}</p>
          <p className="v3-small" style={{ marginTop: 6 }}>
            The audit does not depend on this step. You can continue.
          </p>
        </div>
      ) : null}

      {tools === null && !error ? (
        <div className="v3-empty">Reading the repository...</div>
      ) : null}

      {tools !== null && groups.length === 0 && !error ? (
        <div className="v3-empty">
          We did not recognise a database, auth provider or host in this repository. The
          audit still runs on your code.
        </div>
      ) : null}

      {groups.map(({ category, found }) => (
        <div key={category.id} className="v3-tile">
          <div className="v3-between" style={{ alignItems: "flex-start" }}>
            <div style={{ minWidth: 0 }}>
              <strong style={{ fontWeight: 500, fontSize: 14.5 }}>{category.label}</strong>
              <p className="v3-small" style={{ marginTop: 3 }}>
                {found.map((t) => t.name).join(", ")}
              </p>
            </div>
            <span className="v3-tag">Read from code</span>
          </div>
          <p className="v3-sub" style={{ fontSize: 13, marginTop: 10 }}>
            Not covered by this audit: {lowerFirst(category.adds)}
          </p>
          <p className="v3-file" style={{ marginTop: 8 }}>{found[0].evidence}</p>
        </div>
      ))}

      {authUnknown && tools !== null ? (
        <div className="v3-card v3-card-warn v3-card-p">
          <p style={{ fontWeight: 500, fontSize: 14 }}>No auth provider recognised</p>
          <p className="v3-sub" style={{ fontSize: 13.5, marginTop: 6 }}>
            Your code may handle sign-in itself, which is common. Findings that depend on
            who is calling stay inferred, because we cannot tell an unguarded route from
            one protected by something we do not recognise.
          </p>
        </div>
      ) : null}

      {routeAnalysis?.level === "inventory_only" ? (
        <div className="v3-card v3-card-warn v3-card-p">
          <p style={{ fontWeight: 500, fontSize: 14 }}>Repository inventory only</p>
          <p className="v3-sub" style={{ fontSize: 13.5, marginTop: 6 }}>
            {routeAnalysis.reason} We will still check framework-independent credential and
            configuration evidence, but we will not claim that this repository&apos;s routes or
            authorization paths were assessed.
          </p>
        </div>
      ) : null}

      <div className="v3-row">
        <button className="v3-btn v3-primary" onClick={onContinue}>
          {routeAnalysis?.level === "inventory_only" ? "Run repository checks" : "Run the first audit"} <ArrowRight size={15} />
        </button>
        <span className="v3-small">Coverage keeps this list after the audit runs.</span>
      </div>
    </div>
  );
}

function FirstAudit({ repository, onDone }: { repository: string | undefined; onDone: () => void }) {
  const [trace, setTrace] = useState<TraceStep[]>([]);
  const [status, setStatus] = useState<"running" | "done" | "failed">("running");
  const [summary, setSummary] = useState<{ findings: number; entries: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    if (!repository || started.current) return;
    started.current = true;

    void (async () => {
      try {
        const run = await startAndWaitForAudit(repository, (progress) => setTrace(progress.trace ?? []));
        setTrace(run.trace ?? []);
        setSummary({ findings: run.findings_count ?? 0, entries: run.entries_found ?? 0 });
        setStatus("done");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Something went wrong.");
        setStatus("failed");
      }
    })();
  }, [repository]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [trace]);

  return (
    <div className="v3-stack">
      <div>
        <p className="v3-eyebrow">First audit</p>
        <h1 className="v3-serif" style={{ fontSize: 30, margin: "12px 0 10px" }}>
          {status === "running" ? `Reading ${repository}…` : status === "done" ? "Audit complete." : "The audit stopped."}
        </h1>
        <p className="v3-sub">
          Everything it does is written down. You can read this back for any run, later.
        </p>
      </div>

      <div className="v3-card">
        <div className="v3-hd">
          <div className="v3-row">
            <i className={`v3-dot ${status === "running" ? "run" : status === "done" ? "live" : ""}`} />
            <h2 className="v3-eyebrow">{status === "running" ? "Running" : status === "done" ? "Finished" : "Stopped"}</h2>
          </div>
          {summary ? <span className="v3-small">{summary.entries} entries mapped</span> : null}
        </div>
        <div ref={scrollRef} className="v3-card-p" style={{ maxHeight: 340, overflowY: "auto" }}>
          {trace.length === 0 ? (
            <p className="v3-small">Cloning and reading the repository…</p>
          ) : (
            <div className="v3-trace">
              {trace.map((s, i) => (
                <div key={`${s.time}-${i}`} className={`v3-trace-line${s.found ? " found" : ""}`}>
                  <span className="v3-trace-t">{s.time}</span>
                  <span>
                    <b style={{ fontWeight: 400 }}>{s.label}</b>
                    {s.note ? <small>{s.note}</small> : null}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {error ? <div className="v3-card v3-card-p" style={{ borderColor: "var(--crit)" }}>{error}</div> : null}

      {status !== "running" ? (
        <div className="v3-card v3-card-p v3-between">
          <div>
            <b style={{ fontWeight: 500 }}>
              {summary
                ? `${summary.findings} open ${summary.findings === 1 ? "path" : "paths"}.`
                : "Nothing was recorded for this run."}
            </b>
            <p className="v3-small" style={{ marginTop: 3 }}>
              Everything we could not cover is listed under Coverage.
            </p>
          </div>
          <button className="v3-btn v3-primary" onClick={onDone}>Open the results</button>
        </div>
      ) : null}
    </div>
  );
}
