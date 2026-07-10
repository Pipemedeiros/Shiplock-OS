"use client";

// DIRECTION D · ON RETAINER — dashboard, v3.
// Same theme as the landing: navy band on top, porcelain below. The Lock
// sits centered on the band — white face, bronze dial — and closes when
// the last check verifies. Below: the coverage board with receipts, the
// engagement log, and at the bottom a queue of templated fix PRs waiting
// for the owner's approval (never the data layer — policy).

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import {
  CHECKS,
  DISCLAIMER,
  FINDINGS,
  MOCK_PROJECT,
  NO_PR_POLICY,
  SEVERITY_LABEL,
  SEVERITY_RANK,
  STACK_SPEAKS,
  TIMELINE,
  type Check,
  type Finding,
  type FixPr,
} from "../../_shared/data";
import { Cloud, Database, GitBranch, Sparkles } from "lucide-react";
import { Receipt, receiptFor } from "../Receipt";
import { Lock, type PinState } from "../Lock";
import { CountUp } from "../bits";
import { LockMark } from "../Brand";

type FixPhase = "idle" | "working" | "verified";
type PrState = "pending" | "merging" | "merged";
type SourceState = "off" | "connecting" | "on";

interface LogRow {
  time: string;
  tag: "sweep" | "alert" | "verified" | "pr" | "filed";
  msg: string;
  fresh?: boolean;
}

interface QueuedPr extends FixPr {
  id: string;
  num: number;
  note: string;
  findingId?: string; // wired to a board finding when merging resolves it
}

const SEED_LOG: LogRow[] = [...TIMELINE]
  .sort((a, b) => b.daysAgo - a.daysAgo)
  .map((t) => ({
    time: `D-${String(t.daysAgo).padStart(2, "0")}`,
    tag:
      t.kind === "finding"
        ? ("alert" as const)
        : t.kind === "resolved"
          ? ("verified" as const)
          : ("sweep" as const),
    msg: t.note,
  }))
  .concat([
    { time: "14:02", tag: "sweep", msg: "Hourly sweep — 15 receipts filed, 4 findings held" },
  ]);

const SWEEP_POOL = [
  "probe 02 table enumeration — refused, receipt filed",
  "probe 04 storage buckets — refused, receipt filed",
  "probe 09 auth rate limiting — holding, receipt filed",
  "probe 12 cors policy — holding, receipt filed",
  "probe 14 sql injection surface — refused, receipt filed",
];

const CSP = FINDINGS.find((f) => f.id === "csp-headers")!;

const PR_QUEUE: QueuedPr[] = [
  {
    id: "pr-headers",
    num: 47,
    note: "Closes the open finding: missing browser security headers.",
    findingId: "csp-headers",
    ...CSP.pr!,
  },
  {
    id: "pr-next",
    num: 46,
    note: "Patches a disclosed denial-of-service issue in the framework's image handling.",
    title: "chore(deps): bump next 16.2.7 → 16.2.9",
    branch: "shiplock/bump-next",
    diff: [
      "  // package.json",
      "-   \"next\": \"16.2.7\",",
      "+   \"next\": \"16.2.9\",",
    ],
  },
  {
    id: "pr-zod",
    num: 45,
    note: "Patches a disclosed regex denial-of-service in input validation.",
    title: "chore(deps): bump zod 4.4.1 → 4.4.3",
    branch: "shiplock/bump-zod",
    diff: [
      "  // package.json",
      "-   \"zod\": \"4.4.1\",",
      "+   \"zod\": \"4.4.3\",",
    ],
  },
];

export default function RetainerDashboard() {
  const [resolved, setResolved] = useState<Set<string>>(new Set());
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  const [openRow, setOpenRow] = useState<number | null>(null);
  const [fixPhase, setFixPhase] = useState<Record<string, FixPhase>>({});
  const [prStates, setPrStates] = useState<Record<string, PrState>>({});
  const [diffOpen, setDiffOpen] = useState<string | null>(null);
  const [log, setLog] = useState<LogRow[]>(SEED_LOG);
  const [copied, setCopied] = useState<string | null>(null);
  const [clock, setClock] = useState("--:--:--");
  const [sources, setSources] = useState<{ github: SourceState; vercel: SourceState }>(
    { github: "off", vercel: "off" }
  );
  const rowRefs = useRef<Record<number, HTMLElement | null>>({});
  const queueRef = useRef<HTMLElement | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    let sec = 14 * 3600 + 12 * 60 + 5;
    const t = setInterval(() => {
      sec += 1;
      const h = String(Math.floor(sec / 3600) % 24).padStart(2, "0");
      const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
      const s = String(sec % 60).padStart(2, "0");
      setClock(`${h}:${m}:${s}`);
    }, 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let i = 0;
    let min = 12;
    const t = setInterval(() => {
      const msg = SWEEP_POOL[i % SWEEP_POOL.length];
      i += 1;
      min += 1;
      setLog((l) => [
        ...l.slice(-14),
        { time: `14:${String(min).padStart(2, "0")}`, tag: "sweep", msg, fresh: true },
      ]);
    }, 9000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const findingOf = new Map(FINDINGS.map((f) => [f.checkId, f]));
  const isOpen = (f: Finding) => !resolved.has(f.id);
  const openFindings = FINDINGS.filter(isOpen);
  const needs = openFindings.length;
  const secured = CHECKS.length - needs;
  const worst = [...openFindings].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  )[0];
  const pendingPrs = PR_QUEUE.filter((p) => (prStates[p.id] ?? "pending") === "pending").length;

  const rows: Check[] = [...CHECKS].sort((a, b) => {
    const fa = findingOf.get(a.id);
    const fb = findingOf.get(b.id);
    const oa = fa && isOpen(fa) ? SEVERITY_RANK[fa.severity] : 10;
    const ob = fb && isOpen(fb) ? SEVERITY_RANK[fb.severity] : 10;
    return oa - ob || a.id - b.id;
  });

  const pinStates: Record<number, PinState> = {};
  for (const f of FINDINGS) {
    pinStates[f.checkId] = resolved.has(f.id)
      ? fresh.has(f.id)
        ? "fresh"
        : "verified"
      : "needs";
  }

  function appendLog(tag: LogRow["tag"], msg: string) {
    setLog((l) => [...l.slice(-14), { time: "14:20", tag, msg, fresh: true }]);
  }

  function jumpToCheck(checkId: number) {
    setOpenRow(checkId);
    timers.current.push(
      setTimeout(() => {
        rowRefs.current[checkId]?.scrollIntoView({
          behavior: "smooth",
          block: "center",
        });
      }, 60)
    );
  }

  function completeFinding(f: Finding, logMsg: string) {
    setResolved((r) => new Set(r).add(f.id));
    setFresh((s) => new Set(s).add(f.id));
    appendLog("verified", logMsg);
  }

  function markApplied(f: Finding) {
    setFixPhase((p) => ({ ...p, [f.id]: "working" }));
    timers.current.push(
      setTimeout(() => {
        setFixPhase((p) => ({ ...p, [f.id]: "verified" }));
        completeFinding(f, `Re-probed ${f.tech} — fixed, fresh receipt filed`);
      }, 2100)
    );
  }

  function approvePr(pr: QueuedPr) {
    setPrStates((p) => ({ ...p, [pr.id]: "merging" }));
    appendLog("pr", `PR #${pr.num} approved: ${pr.title}`);
    timers.current.push(
      setTimeout(() => {
        setPrStates((p) => ({ ...p, [pr.id]: "merged" }));
        const f = pr.findingId
          ? FINDINGS.find((x) => x.id === pr.findingId)
          : undefined;
        if (f) {
          completeFinding(f, `PR #${pr.num} merged — re-probed, fresh receipt filed`);
        } else {
          appendLog("verified", `PR #${pr.num} merged — dependency verified clean`);
        }
      }, 2000)
    );
  }

  function connectSource(key: "github" | "vercel") {
    setSources((s) => ({ ...s, [key]: "connecting" }));
    timers.current.push(
      setTimeout(() => {
        setSources((s) => ({ ...s, [key]: "on" }));
        appendLog(
          "filed",
          key === "github"
            ? "GitHub connected — contents: read-only · fix PRs and source scanning armed"
            : "Vercel connected — read-only, selected projects · env audit armed"
        );
      }, 900)
    );
  }

  async function copy(text: string, key: string) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // mocked page — the state change is the demo
    }
    setCopied(key);
    setTimeout(() => setCopied((c) => (c === key ? null : c)), 1600);
  }

  const checksThisMonth = 1284 + resolved.size;

  return (
    <main className="dxd">
      <div className="dxd-band">
        <div className="dxd-shell">
          <nav className="dxd-nav" aria-label="Main">
            <Link href="/design/d" className="dxd-wordmark">
              <span className="dxd-wordmark-lock">
                <LockMark size={19} />
              </span>
              ShipLock
            </Link>
            <div className="dxd-nav-links">
              <span className="dxd-mono" style={{ fontSize: 12, color: "var(--d-muted-light)" }}>
                {MOCK_PROJECT.appUrl}
              </span>
              <span className="dxd-mono" style={{ fontSize: 12 }}>
                {clock} UTC
              </span>
              <a href="#terms">Retainer · $49/mo</a>
            </div>
          </nav>

          <header className="dxd-dash-hero">
            <p className="dxd-eyebrow">The coverage board</p>
            <h1 className="dxd-statement" aria-live="polite">
              {needs === 0 ? (
                <>
                  Locked. You&apos;re <em className="dxd-em-ok">covered.</em>
                </>
              ) : (
                <>
                  {["", "One thing", "Two things", "Three things", "Four things"][needs] ||
                    `${needs} things`}{" "}
                  <em>need{needs === 1 ? "s" : ""} you.</em> We hold the rest.
                </>
              )}
            </h1>

            <Lock states={pinStates} secured={secured} onSelect={jumpToCheck} />

            <div className="dxd-substat">
              <span>
                <b>
                  <CountUp to={checksThisMonth} />
                </b>{" "}
                receipts this month
              </span>
              <span>
                worst open:{" "}
                <b>{worst ? SEVERITY_LABEL[worst.severity].toLowerCase() : "none"}</b>
              </span>
              <span>
                next sweep <b>15:00 UTC</b>
              </span>
              <span>
                fix PRs waiting{" "}
                <b>{sources.github === "on" ? pendingPrs : "connect github"}</b>
              </span>
            </div>
          </header>
        </div>
      </div>

      <div className="dxd-shell dxd-dash-body">
        <section aria-label="Your connected stack">
          <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
            Your stack · what the watch can see
          </p>
          <div className="dxd-stack">
            <div className="dxd-stack-tile">
              <span className="dxd-stack-glyph">
                <Database size={20} strokeWidth={1.8} aria-hidden="true" />
              </span>
              <span className="dxd-stack-name">
                <span className="dxd-stack-cat">Database</span>
                <h3>{MOCK_PROJECT.stack.database}</h3>
                <span className="dxd-stack-role">public key only, never more</span>
              </span>
              <span className="dxd-stack-status dxd-chip dxd-chip-verified">
                Connected
              </span>
            </div>

            <div className="dxd-stack-tile">
              <span className="dxd-stack-glyph">
                <Cloud size={20} strokeWidth={1.8} aria-hidden="true" />
              </span>
              <span className="dxd-stack-name">
                <span className="dxd-stack-cat">Host</span>
                <h3>{MOCK_PROJECT.stack.host}</h3>
                <span className="dxd-stack-role">read-only, selected projects</span>
              </span>
              <span className="dxd-stack-status">
                {sources.vercel === "on" ? (
                  <span className="dxd-chip dxd-chip-verified">Connected</span>
                ) : sources.vercel === "connecting" ? (
                  <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)" }}>
                    connecting…
                  </span>
                ) : (
                  <button
                    type="button"
                    className="dxd-btn dxd-btn-ghost dxd-btn-sm"
                    onClick={() => connectSource("vercel")}
                  >
                    Connect
                  </button>
                )}
              </span>
            </div>

            <div className="dxd-stack-tile">
              <span className="dxd-stack-glyph">
                <GitBranch size={20} strokeWidth={1.8} aria-hidden="true" />
              </span>
              <span className="dxd-stack-name">
                <span className="dxd-stack-cat">Source</span>
                <h3>{MOCK_PROJECT.stack.source}</h3>
                <span className="dxd-stack-role">contents: read-only</span>
              </span>
              <span className="dxd-stack-status">
                {sources.github === "on" ? (
                  <span className="dxd-chip dxd-chip-verified">Connected</span>
                ) : sources.github === "connecting" ? (
                  <span className="dxd-mono" style={{ fontSize: 11, color: "var(--d-muted)" }}>
                    connecting…
                  </span>
                ) : (
                  <button
                    type="button"
                    className="dxd-btn dxd-btn-ghost dxd-btn-sm"
                    onClick={() => connectSource("github")}
                  >
                    Connect
                  </button>
                )}
              </span>
            </div>

            <div className="dxd-stack-tile">
              <span className="dxd-stack-glyph">
                <Sparkles size={20} strokeWidth={1.8} aria-hidden="true" />
              </span>
              <span className="dxd-stack-name">
                <span className="dxd-stack-cat">Builder</span>
                <h3>{MOCK_PROJECT.stack.builder}</h3>
                <span className="dxd-stack-role">detected — nothing to connect</span>
              </span>
              <span className="dxd-stack-status dxd-chip dxd-chip-detected">
                Detected
              </span>
            </div>
          </div>
          <p className="dxd-stack-note">
            Slots, not brands — database{" "}
            {STACK_SPEAKS.database.join(" or ")} · host{" "}
            {STACK_SPEAKS.host.join(" or ")} · built with{" "}
            {STACK_SPEAKS.builder.join(", ")}. The watch adapts to the stack
            it finds.
          </p>
        </section>

        <div className="dxd-dashgrid">
          <section className="dxd-board" aria-label="Coverage board — 15 checks">
            <div className="dxd-board-head">
              <span>Check · claim</span>
              <span>Every claim has a receipt</span>
            </div>

            {rows.map((c) => {
              const f = findingOf.get(c.id);
              const active = f && isOpen(f);
              const justVerified = f && fresh.has(f.id);
              const opened = openRow === c.id;
              const receipt = receiptFor(c.id, c.name, Boolean(active));

              return (
                <article
                  key={c.id}
                  ref={(el) => {
                    rowRefs.current[c.id] = el;
                  }}
                  className={`dxd-row ${justVerified ? "dxd-fresh" : ""}`}
                  data-needs={Boolean(active)}
                  data-open={opened}
                >
                  <button
                    type="button"
                    className="dxd-row-btn"
                    aria-expanded={opened}
                    onClick={() => setOpenRow(opened ? null : c.id)}
                  >
                    {active ? (
                      <span className={`dxd-chip dxd-chip-${f.severity}`}>
                        {SEVERITY_LABEL[f.severity]}
                      </span>
                    ) : (
                      <span className="dxd-chip dxd-chip-verified">Verified</span>
                    )}
                    <span className="dxd-row-name">
                      <h3>{active ? f.title : c.name}</h3>
                      <span className="dxd-tech">
                        {active
                          ? f.tech
                          : `${String(c.id).padStart(2, "0")} · ${c.surface.toLowerCase()}`}
                      </span>
                    </span>
                    <span className="dxd-row-time">
                      {active
                        ? `flagged ${f.detectedAgo}`
                        : justVerified
                          ? "verified just now"
                          : "verified 14:02:04"}
                    </span>
                    <span className="dxd-row-chevron" aria-hidden="true">
                      ▾
                    </span>
                  </button>

                  {opened && (
                    <div className="dxd-row-body">
                      {active && (
                        <>
                          <p>
                            <strong>What&apos;s happening — </strong>
                            {f.plain}
                          </p>
                          <p>
                            <strong>What it costs you if it stays — </strong>
                            {f.consequence}
                          </p>
                        </>
                      )}

                      {justVerified && !active && (
                        <p>
                          <strong>Closed and verified. </strong>
                          The weight moved back to us — this check re-runs
                          every sweep, and if it ever regresses it comes
                          straight back to the top of the board.
                        </p>
                      )}

                      <Receipt
                        label={active ? "Finding receipt" : "Verification receipt"}
                        refNo={`№ 2026-${1200 + c.id}`}
                        data={receipt}
                        stampLeft={MOCK_PROJECT.appUrl}
                        stampRight={
                          active
                            ? `filed ${f.detectedAgo}`
                            : justVerified
                              ? "verified just now"
                              : "verified 14:02:04 UTC"
                        }
                      />

                      {active && (
                        <div className="dxd-brief">
                          <p className="dxd-brief-title">
                            The brief · prepared for you
                          </p>
                          <ol>
                            {f.steps.map((s, i) => (
                              <li key={s.title}>
                                <h4>{s.title}</h4>
                                <p>{s.body}</p>
                                {i === 1 && f.sql && (
                                  <pre className="dxd-code">{f.sql}</pre>
                                )}
                                {i === 1 && (
                                  <div className="dxd-brief-actions">
                                    {f.sql && (
                                      <button
                                        type="button"
                                        className="dxd-btn dxd-btn-ghost"
                                        onClick={() => copy(f.sql!, `${f.id}-sql`)}
                                      >
                                        {copied === `${f.id}-sql`
                                          ? "Copied"
                                          : "Copy the SQL"}
                                      </button>
                                    )}
                                    <button
                                      type="button"
                                      className="dxd-btn dxd-btn-ghost"
                                      onClick={() => copy(f.aiPrompt, `${f.id}-ai`)}
                                    >
                                      {copied === `${f.id}-ai`
                                        ? "Copied"
                                        : "Copy the prompt for your AI tool"}
                                    </button>
                                  </div>
                                )}
                              </li>
                            ))}
                          </ol>

                          <div className="dxd-brief-actions">
                            {fixPhase[f.id] === "working" ? (
                              <span className="dxd-working" role="status">
                                <i />
                                <i />
                                <i />
                                Re-running the probe against your live app…
                              </span>
                            ) : (
                              <>
                                <button
                                  type="button"
                                  className="dxd-btn"
                                  onClick={() => markApplied(f)}
                                >
                                  I&apos;ve applied it — verify
                                </button>
                                <span
                                  className="dxd-mono"
                                  style={{ fontSize: 11.5, color: "var(--d-muted)" }}
                                >
                                  we re-probe and file a fresh receipt
                                </span>
                              </>
                            )}
                          </div>

                          {f.pr ? (
                            sources.github === "on" ? (
                              <p className="dxd-policy-note">
                                This one is safely templatable — a fix PR is
                                waiting for your approval in the queue below.{" "}
                                <button
                                  type="button"
                                  className="dxd-btn-quiet"
                                  style={{ padding: "2px 6px" }}
                                  onClick={() =>
                                    queueRef.current?.scrollIntoView({
                                      behavior: "smooth",
                                      block: "center",
                                    })
                                  }
                                >
                                  Review it ↓
                                </button>
                              </p>
                            ) : (
                              <p className="dxd-policy-note">
                                This one is safely templatable — connect
                                GitHub (contents: read-only) and we&apos;ll
                                open a fix PR for your approval.{" "}
                                <button
                                  type="button"
                                  className="dxd-btn-quiet"
                                  style={{ padding: "2px 6px" }}
                                  onClick={() => connectSource("github")}
                                >
                                  Connect GitHub
                                </button>
                              </p>
                            )
                          ) : (
                            <p className="dxd-policy-note">{NO_PR_POLICY}</p>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </article>
              );
            })}
          </section>

          <aside className="dxd-rail">
            <div className="dxd-panel">
              <p className="dxd-panel-label">Engagement log</p>
              <div className="dxd-log" role="log" aria-live="polite">
                {log.map((r, i) => (
                  <div
                    className={`dxd-log-row ${r.fresh ? "dxd-log-fresh" : ""}`}
                    data-tag={r.tag}
                    key={`${r.time}-${i}`}
                  >
                    <span className="dxd-log-time">{r.time}</span>
                    <span className="dxd-log-msg">{r.msg}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="dxd-panel" id="terms">
              <p className="dxd-panel-label">Terms of engagement</p>
              <div
                className="dxd-substat"
                style={{ flexDirection: "column", gap: 10, alignItems: "flex-start" }}
              >
                <span>
                  plan <b>the retainer · $49/mo</b>
                </span>
                <span>
                  alerts <b>only when something new appears</b>
                </span>
                <span>
                  auto-PRs <b>templated fixes only — never your data layer</b>
                </span>
                <span>
                  silence <b>means everything held</b>
                </span>
              </div>
            </div>
          </aside>
        </div>

        <section
          className="dxd-prqueue"
          aria-label="Fix PRs awaiting your approval"
          ref={queueRef}
        >
          <div className="dxd-board-head">
            <span>Fix PRs · awaiting your approval</span>
            <span>you approve — we never merge for you</span>
          </div>
          {sources.github !== "on" && (
            <div className="dxd-prq-main">
              <span className="dxd-chip dxd-chip-detected">Waiting</span>
              <span className="dxd-prq-title">
                <h3>Connect GitHub to receive fix PRs</h3>
                <span className="dxd-prq-note">
                  Contents read-only, per-repo, revocable. Templated fixes
                  only — headers and dependency bumps. Your data layer is
                  never touched by a bot; that&apos;s policy.
                </span>
              </span>
              <span className="dxd-prq-actions">
                {sources.github === "connecting" ? (
                  <span className="dxd-working" role="status">
                    <i />
                    <i />
                    <i />
                    Connecting…
                  </span>
                ) : (
                  <button
                    type="button"
                    className="dxd-btn"
                    onClick={() => connectSource("github")}
                  >
                    Connect GitHub
                  </button>
                )}
              </span>
            </div>
          )}
          {sources.github === "on" && PR_QUEUE.map((pr) => {
            const state = prStates[pr.id] ?? "pending";
            return (
              <div className="dxd-prq-row" key={pr.id}>
                <div className="dxd-prq-main">
                  {state === "merged" ? (
                    <span className="dxd-chip dxd-chip-verified">Merged</span>
                  ) : (
                    <span className="dxd-chip dxd-chip-pending">Pending</span>
                  )}
                  <span className="dxd-prq-title">
                    <h3>
                      #{pr.num} · {pr.title}
                    </h3>
                    <span className="dxd-prq-note">{pr.note}</span>
                  </span>
                  <span className="dxd-pr-branch">{pr.branch}</span>
                  <span className="dxd-prq-actions">
                    <button
                      type="button"
                      className="dxd-btn-quiet"
                      aria-expanded={diffOpen === pr.id}
                      onClick={() =>
                        setDiffOpen(diffOpen === pr.id ? null : pr.id)
                      }
                    >
                      {diffOpen === pr.id ? "Hide diff" : "View diff"}
                    </button>
                    {state === "pending" && (
                      <button
                        type="button"
                        className="dxd-btn"
                        onClick={() => approvePr(pr)}
                      >
                        Approve &amp; merge
                      </button>
                    )}
                    {state === "merging" && (
                      <span className="dxd-working" role="status">
                        <i />
                        <i />
                        <i />
                        Merging, then re-probing…
                      </span>
                    )}
                    {state === "merged" && (
                      <span
                        className="dxd-mono"
                        style={{ fontSize: 11, color: "var(--d-verified)" }}
                      >
                        verified after merge
                      </span>
                    )}
                  </span>
                </div>
                {diffOpen === pr.id && (
                  <div className="dxd-prq-diff">
                    <div className="dxd-diff">
                      {pr.diff.map((line, i) => (
                        <div
                          key={i}
                          className={`dxd-diff-line ${
                            line.startsWith("+")
                              ? "dxd-diff-add"
                              : "dxd-diff-ctx"
                          }`}
                        >
                          {line}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </section>

        <footer className="dxd-footer">
          <span className="dxd-serif" style={{ fontSize: 15 }}>
            ShipLock<span style={{ color: "var(--d-bronze)" }}>.</span> On
            retainer.
          </span>
          <span>{DISCLAIMER}</span>
        </footer>
      </div>
    </main>
  );
}
