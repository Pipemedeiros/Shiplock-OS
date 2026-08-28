"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Check, GitPullRequest, LockKeyhole, ShieldCheck } from "lucide-react";

/**
 * Onboarding, which is one connection long.
 *
 * GitHub and nothing else. The database connection exists and is worth having
 * -- it is what makes a finding reproducible rather than inferred -- but it is
 * offered afterwards, from Settings, and never blocks a first audit. Asking for
 * a database password before showing anyone a single finding is how a security
 * tool gets abandoned in the first two minutes.
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

type Step = "connect" | "repos" | "audit";

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
              setStep("audit");
            } catch (err) {
              setError(err instanceof Error ? err.message : "Something went wrong.");
            } finally {
              setLoading(false);
            }
          }}
        />
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
          Read-only on the repositories you pick. We do not ask for your database password, your auth
          keys or your payment account — your code names what it talks to.
        </p>
      </div>

      <div className="v3-card">
        <div className="v3-hd">
          <h2 className="v3-eyebrow">What we are asking for</h2>
          <span className="v3-tag ok">Read-only on your code</span>
        </div>
        <div className="v3-card-p">
          {[
            { Icon: LockKeyhole, name: "Repository contents", detail: "Read the code to build the map", access: "read" },
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
            We never push to your default branch. Uninstalling deletes what we read within an hour.
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
          {loading ? "Saving…" : "Run the first audit"}
        </button>
        <span className="v3-small">{picked.length} selected · a few minutes</span>
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
        const res = await fetch("/api/audit", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repository }),
        });
        const json = (await res.json()) as {
          trace?: TraceStep[]; findings?: number; entries?: number; error?: string;
        };
        if (!res.ok) throw new Error(json.error ?? "The audit could not finish.");
        setTrace(json.trace ?? []);
        setSummary({ findings: json.findings ?? 0, entries: json.entries ?? 0 });
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
