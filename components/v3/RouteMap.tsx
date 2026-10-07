"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { forceLayout } from "@/lib/graphLayout";
import {
  placeLabels, simulateRequest, type Attacker, type Exposure, type MapEdge, type MapNode, type RouteMap as RouteMapData, type Simulation,
} from "@/lib/routeMap";

/**
 * The application's map as an Obsidian-style graph (Felipe 2026-10-06: not
 * 3D, like Obsidian, full creative freedom inside v3's palette and fonts).
 * Routes, the security checks they pass, the tables they reach and the
 * services behind them, laid out by force (lib/graphLayout.ts) from the same
 * route facts as the audit. Colour is reserved for risk; shape carries kind.
 * Hover or focus a node to light its neighbours; drag to pan; pinch or the
 * buttons to zoom. Every node is a keyboard control, and the List view reads
 * the same facts as text.
 *
 * "Simulate a request" plays a request through a route from those facts; it
 * is labelled as a simulation, not live traffic.
 */
type View = { x: number; y: number; k: number };
const HOME: View = { x: 0, y: 0, k: 1 };
const BOX = 340; // half the viewBox: the layout fits a disc of radius 300 inside it

const REDUCED = "(prefers-reduced-motion: reduce)";
const subscribeMotion = (listener: () => void) => {
  const query = window.matchMedia(REDUCED);
  query.addEventListener("change", listener);
  return () => query.removeEventListener("change", listener);
};

// Colour is for risk only (validated on the navy surface: normal-vision ΔE
// 21.4, colour-blind 13.6). Everything safe stays quiet porcelain.
const OPEN = "#ff6a5c", UNSCOPED = "#f0c75e", UNKNOWN = "#9aa5b4", QUIET = "#c3cfdd", DIM = "#3e4c63", HOT = "#e8d3a0";
export const EXPOSURE: Record<Exposure, { color: string; label: string }> = {
  open: { color: OPEN, label: "No sign-in, reaches data" },
  unscoped: { color: UNSCOPED, label: "Signed in, not limited to own rows" },
  unknown: { color: UNKNOWN, label: "A check we could not read" },
  scoped: { color: QUIET, label: "Scoped to the caller" },
  secret: { color: QUIET, label: "Secret or signature" },
  none: { color: DIM, label: "Reaches no table" },
};
const FLOW: Record<NonNullable<MapEdge["risk"]>, string> = { open: OPEN, unscoped: UNSCOPED, unknown: UNKNOWN, guarded: "#9fb0c4" };
const OUTCOME: Record<Simulation["outcome"], { label: string; tone: string }> = {
  stopped: { label: "Stopped", tone: "#9fd3b8" },
  scoped: { label: "Reaches only the caller's rows", tone: QUIET },
  reaches: { label: "Reaches data it should not", tone: "#ff9d85" },
  unknown: { label: "Unknown: a check we could not read", tone: "#e8d3a0" },
};
const RISKY: Exposure[] = ["open", "unscoped", "unknown"];
const GROUP_ORDER: Exposure[] = ["open", "unknown", "unscoped", "scoped", "secret", "none"];
const GROUP: Record<Exposure, string> = { open: "No sign in", unknown: "Could not read", unscoped: "Not limited to own rows",
  scoped: "Own rows only", secret: "Secret required", none: "No data" };

/**
 * The nodes a simulated request passes, in order, along the map's own edges:
 * the route, the controls it meets, then (if it gets through) the tables.
 * A stopped request ends at the control that stops it.
 */
export function simulationPath(map: RouteMapData, routeId: string, sim: Simulation): string[] {
  const out = (id: string, kind: MapEdge["kind"]) => map.edges.filter((e) => e.from === id && e.kind === kind).map((e) => e.to);
  // Checks are shared nodes: the sign-in check links on to the scope check
  // for the routes that have it. Only this route's own facts decide whether
  // its request goes there.
  const scoped = map.nodes.find((n) => n.id === routeId)?.exposure === "scoped";
  const path = [routeId];
  let at = routeId;
  for (;;) {
    const next = out(at, "guard").find((id) => id.startsWith("control:") && (id !== "control:scope" || scoped));
    if (!next) break;
    path.push(next);
    at = next;
    if (sim.outcome === "stopped") return path;
  }
  if (sim.outcome === "reaches" || sim.outcome === "scoped") {
    const tables = new Set(out(at, "flow"));
    for (const t of sim.reached) if (tables.has(`table:${t}`)) path.push(`table:${t}`);
  }
  return path;
}

function describe(node: MapNode): { status: string; tone: string; action?: { href: string; label: string } } {
  if (node.kind === "provider") {
    return node.connection === "available"
      ? { status: "Detected · live connection available", tone: "#7fc4a0", action: { href: "/dashboard/stack", label: "Connect read only" } }
      : { status: "Detected · live connection coming soon", tone: "#9fb0c4" };
  }
  if (node.kind === "table") return { status: "Table", tone: QUIET };
  if (node.kind === "control") return { status: "Security check read in your code", tone: QUIET };
  if (node.kind === "helper") return { status: "Shared code", tone: QUIET };
  if (node.finding) {
    return { status: node.finding === "CRITICAL" ? "Open critical finding" : "Open finding", tone: node.finding === "CRITICAL" ? "#ff9d85" : UNSCOPED,
      action: { href: "/dashboard/risks", label: "Review the finding" } };
  }
  if (node.hot) return { status: "Heavy traffic observed", tone: HOT, action: { href: "/dashboard/risks", label: "See the rate limit offer" } };
  const e = EXPOSURE[node.exposure ?? "none"];
  return { status: e.label, tone: e.color === DIM ? "#9fb0c4" : e.color };
}

const ariaLabel = (n: MapNode) =>
  `${n.kind === "helper" ? "shared code" : n.kind === "control" ? "security check" : n.kind} ${n.label}`
  + `${n.exposure ? `, ${EXPOSURE[n.exposure].label}` : ""}${n.finding ? `, open ${n.finding.toLowerCase()} finding` : ""}`;
const labelText = (n: MapNode) => `${n.label}${n.kind === "provider" && n.connection === "coming_soon" ? " · coming soon" : ""}`;

/** One node's mark: circle (route), rounded square (table), diamond (check), ring (service), dot (shared code). */
function Mark({ n, r }: { n: MapNode; r: number }) {
  if (n.kind === "table") return <rect x={-r * 0.8} y={-r * 0.8} width={1.6 * r} height={1.6 * r} rx={1.5} fill="#aebccd" />;
  if (n.kind === "control") return <path d={`M0 ${-r} L${r} 0 L0 ${r} L${-r} 0 Z`} fill="#0f1b2d" stroke="#eef2f7" strokeWidth={1.6} vectorEffect="non-scaling-stroke" />;
  if (n.kind === "provider") {
    return <circle r={r} fill="#0f1b2d" stroke={n.connection === "available" ? "#7fc4a0" : "#9fb0c4"} strokeWidth={1.6}
      strokeDasharray={n.connection === "available" ? undefined : "3 3"} vectorEffect="non-scaling-stroke" />;
  }
  if (n.kind === "helper") return <circle r={r} fill="#6f84a6" />;
  const exposure = n.exposure ?? "none";
  return (
    <>
      {n.finding ? <circle r={r + 5} fill="none" stroke={EXPOSURE[exposure].color} strokeOpacity={0.4} strokeWidth={1.2} vectorEffect="non-scaling-stroke" /> : null}
      {n.hot ? <circle r={r + 8} fill="none" stroke={HOT} strokeDasharray="2 3" strokeWidth={1} vectorEffect="non-scaling-stroke" /> : null}
      {exposure === "unknown"
        ? <circle r={r} fill="#0f1b2d" stroke={UNKNOWN} strokeWidth={1.6} strokeDasharray="2 2" vectorEffect="non-scaling-stroke" />
        : exposure === "secret"
          ? <circle r={r} fill="#0f1b2d" stroke={QUIET} strokeWidth={1.6} vectorEffect="non-scaling-stroke" />
          : <circle r={r} fill={EXPOSURE[exposure].color} />}
    </>
  );
}

/** The same facts as text: routes by exposure, worst first, with what each reaches. */
export function MapList({ map, visible, selected, onSelect }: {
  map: RouteMapData; visible: Set<string>; selected: string; onSelect: (id: string) => void;
}) {
  const reaches = (id: string) => {
    const seen = new Set<string>([id]);
    const tables = new Set<string>();
    for (let frontier = [id]; frontier.length;) {
      const next: string[] = [];
      for (const e of map.edges) if (frontier.includes(e.from) && !seen.has(e.to) && e.kind !== "shared" && e.kind !== "store") {
        seen.add(e.to); next.push(e.to);
        if (e.to.startsWith("table:")) tables.add(e.to.slice(6));
      }
      frontier = next;
    }
    return [...tables];
  };
  const routes = map.nodes.filter((n) => n.kind === "route" && visible.has(n.id));
  return (
    <div className="v3-graph-list">
      {GROUP_ORDER.map((g) => {
        const rows = routes.filter((n) => (n.exposure ?? "none") === g);
        if (rows.length === 0) return null;
        return (
          <section key={g}>
            <h3><i style={{ background: EXPOSURE[g].color }} />{GROUP[g]} <b>{rows.length}</b></h3>
            <ul>
              {rows.map((n) => {
                const t = reaches(n.id);
                return (
                  <li key={n.id}>
                    <button type="button" aria-pressed={n.id === selected} onClick={() => onSelect(n.id)}>{n.label}</button>
                    <span>{t.length ? `reaches ${t.join(", ")}` : "reaches no table"}{n.finding ? ` · open ${n.finding.toLowerCase()} finding` : ""}</span>
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

export function RouteMap({ map }: { map: RouteMapData }) {
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ x: number; y: number; view: View; moved: boolean } | null>(null);
  const [stage, setStage] = useState({ height: 540, aspect: 1.6 });
  const [view, setView] = useState<View>(HOME);
  const motionOk = useSyncExternalStore(subscribeMotion, () => !window.matchMedia(REDUCED).matches, () => false);
  const [paused, setPaused] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [focus, setFocus] = useState<string | null>(null);
  const [showShared, setShowShared] = useState(false);
  const [riskyOnly, setRiskyOnly] = useState(false);
  const [list, setList] = useState(false);
  const [selected, setSelected] = useState<string>(() =>
    (map.nodes.find((n) => n.finding === "CRITICAL") ?? map.nodes.find((n) => n.finding) ?? map.nodes.find((n) => n.exposure === "open")
      ?? map.nodes.find((n) => n.exposure === "unscoped") ?? map.nodes.find((n) => n.id === "control:session")
      ?? map.nodes.find((n) => n.kind === "route") ?? map.nodes[0])?.id ?? "");
  const [attacker, setAttacker] = useState<Attacker>("anonymous");
  const [sim, setSim] = useState<{ routeId: string; result: Simulation; path: string[]; progress: number } | null>(null);

  // One layout for every node, shared code included, so toggling a filter
  // never reshuffles the picture.
  const disc = useMemo(() => forceLayout(map.nodes.map((n) => n.id), map.edges, { radius: 300 }), [map]);
  const layout = useMemo(() => new Map([...disc].map(([id, p]) => [id, { x: p.x * stage.aspect, y: p.y }])), [disc, stage.aspect]);
  const degree = useMemo(() => {
    const d = new Map<string, number>();
    for (const e of map.edges) { d.set(e.from, (d.get(e.from) ?? 0) + 1); d.set(e.to, (d.get(e.to) ?? 0) + 1); }
    return d;
  }, [map]);
  const radiusOf = (n: MapNode) => n.kind === "provider" ? 11 : n.kind === "control" ? 9 : n.kind === "helper" ? 3
    : Math.min(10, 3.5 + 1.4 * Math.sqrt(degree.get(n.id) ?? 0));

  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    // The graph widens to the stage (a disc in a wide panel wastes its sides).
    const observer = new ResizeObserver(([entry]) => {
      const height = entry.contentRect.width < 560 ? 400 : 540;
      setStage({ height, aspect: Math.max(1, Math.min(1.8, entry.contentRect.width / height)) });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Pinch on a trackpad (ctrl + wheel) zooms; a plain wheel keeps scrolling the
  // page. Registered natively so the page does not zoom instead.
  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      setView((v) => ({ ...v, k: Math.max(0.5, Math.min(4, v.k * Math.exp(-e.deltaY / 300))) }));
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  const simKey = sim ? `${sim.routeId}|${sim.path.length}|${sim.result.outcome}` : null;
  useEffect(() => {
    if (!simKey) return;
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      let more = false;
      setSim((s) => {
        if (!s) return s;
        const hops = s.path.length - 1;
        const progress = Math.min(hops, (now - start) / 700);
        more = progress < hops;
        return progress === s.progress ? s : { ...s, progress };
      });
      if (more) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [simKey]);

  // What is shown: shared code only when asked; "only exposed paths" keeps
  // exposed routes and everything their data reaches.
  const visible = useMemo(() => {
    const keep = new Set<string>();
    const risky = new Set(map.nodes.filter((n) => n.kind === "route" && RISKY.includes(n.exposure ?? "none")).map((n) => n.id));
    for (const n of map.nodes) {
      if (n.kind === "helper" && !showShared) continue;
      if (riskyOnly && n.kind === "route" && !risky.has(n.id)) continue;
      keep.add(n.id);
    }
    if (riskyOnly) {
      const reach = new Set<string>(risky);
      for (let changed = true; changed;) {
        changed = false;
        for (const e of map.edges) if (reach.has(e.from) && !reach.has(e.to) && e.kind !== "shared") { reach.add(e.to); changed = true; }
      }
      for (const id of [...keep]) if (!reach.has(id) && !id.startsWith("helper:")) keep.delete(id);
    }
    return keep;
  }, [map, showShared, riskyOnly]);

  // The lit neighbourhood: the hovered or focused node and everything one edge away.
  const lit = useMemo(() => {
    if (!focus) return null;
    const s = new Set([focus]);
    for (const e of map.edges) { if (e.from === focus) s.add(e.to); if (e.to === focus) s.add(e.from); }
    return s;
  }, [focus, map.edges]);

  const node = map.nodes.find((n) => n.id === selected);
  const info = node ? describe(node) : null;
  const hops = sim ? sim.path.length - 1 : 0;
  const reachedIndex = sim ? Math.floor(sim.progress) : -1;
  const onPath = new Set(sim ? sim.path.slice(0, reachedIndex + 1) : []);
  const done = sim !== null && sim.progress >= hops;
  const stepsShown = sim ? (done ? sim.result.steps.length : Math.min(sim.result.steps.length - 1, reachedIndex + 1)) : 0;
  const drifting = motionOk && !paused && !focus && !sim && !dragging;
  const counts = map.nodes.filter((n) => n.kind === "route").reduce<Record<string, number>>((acc, n) => {
    const k = n.exposure ?? "none"; acc[k] = (acc[k] ?? 0) + 1; return acc;
  }, {});

  function select(id: string) { setSelected(id); setSim(null); }
  function run() {
    if (!node?.fact) return;
    const result = simulateRequest(node.fact, attacker);
    const path = simulationPath(map, node.id, result);
    setSim({ routeId: node.id, result, path, progress: motionOk ? 0 : path.length - 1 });
  }

  let pulse: { x: number; y: number } | null = null;
  if (sim && !done) {
    const i = reachedIndex, t = sim.progress - i;
    const a = layout.get(sim.path[i]), b = layout.get(sim.path[i + 1]);
    if (a && b) pulse = { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
  }

  // Labels, Obsidian style: the nodes that matter always try; the rest appear
  // as you zoom in, or when lit. Placed in screen space so they never collide.
  const font = 11;
  const shown = placeLabels(map.nodes.filter((n) => visible.has(n.id)).map((n) => {
    const p = layout.get(n.id)!;
    const important = n.kind !== "route" && n.kind !== "helper" || Boolean(n.finding) || Boolean(n.hot);
    const force = n.id === selected || onPath.has(n.id) || n.id === focus;
    const wanted = important || view.k >= 1.8 || (lit?.has(n.id) ?? false);
    const r = radiusOf(n);
    return { id: n.id, x: (p.x * view.k) + r * view.k + 4, y: (p.y * view.k) - font / 2, w: labelText(n).length * font * 0.6 + 4, h: font + 4,
      priority: wanted ? (n.kind === "control" ? 6 : n.finding ? 5 : n.kind === "provider" ? 4 : n.hot ? 3 : lit?.has(n.id) ? 2 : 1) : -1, force };
  }).filter((b) => b.force || b.priority >= 0));

  function nudge(dx: number, dy: number) { setView((v) => ({ ...v, x: v.x + dx, y: v.y + dy })); }

  return (
    <div className="v3-map">
      <div className="v3-map-stage">
        <div className="v3-map-toolbar" role="group" aria-label="Map view">
          <button type="button" aria-pressed={riskyOnly} onClick={() => setRiskyOnly((v) => !v)}>Only exposed paths</button>
          <button type="button" aria-pressed={showShared} onClick={() => setShowShared((v) => !v)}>Shared code</button>
          <button type="button" aria-pressed={list} onClick={() => setList((v) => !v)}>List</button>
        </div>
        {list ? (
          <MapList map={map} visible={visible} selected={selected} onSelect={select} />
        ) : (
          <svg
            ref={svg}
            className="v3-graph"
            viewBox={`${-BOX * stage.aspect} ${-BOX} ${2 * BOX * stage.aspect} ${2 * BOX}`}
            preserveAspectRatio="xMidYMid meet"
            style={{ height: stage.height }}
            role="group"
            aria-label={`Map of ${counts.open ?? 0} open, ${counts.unscoped ?? 0} unscoped and ${(counts.scoped ?? 0) + (counts.secret ?? 0)} guarded routes. Use the List view for the same facts as text.`}
            onPointerDown={(e) => {
              if ((e.target as Element).closest(".v3-map-node")) return;
              drag.current = { x: e.clientX, y: e.clientY, view, moved: false };
              setDragging(true);
              (e.currentTarget as Element).setPointerCapture(e.pointerId);
            }}
            onPointerMove={(e) => {
              const d = drag.current;
              if (!d || !svg.current) return;
              const unit = (2 * BOX) / Math.max(1, svg.current.clientHeight);
              d.moved = true;
              setView({ ...d.view, x: d.view.x + (e.clientX - d.x) * unit, y: d.view.y + (e.clientY - d.y) * unit });
            }}
            onPointerUp={() => { drag.current = null; setDragging(false); }}
            onPointerLeave={() => setFocus(null)}
          >
            <defs>
              <radialGradient id="v3-graph-glow" cx="50%" cy="50%" r="55%">
                <stop offset="0%" stopColor="#17273d" />
                <stop offset="100%" stopColor="#0f1b2d" />
              </radialGradient>
            </defs>
            <rect x={-BOX * stage.aspect} y={-BOX} width={2 * BOX * stage.aspect} height={2 * BOX} fill="url(#v3-graph-glow)" />
            <g className={drifting ? "v3-graph-drift" : undefined}>
              <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
                {map.edges.map((e) => {
                  if (!visible.has(e.from) || !visible.has(e.to)) return null;
                  const p = layout.get(e.from), q = layout.get(e.to);
                  if (!p || !q) return null;
                  const risky = e.kind === "flow" && e.risk !== "guarded";
                  const onSim = onPath.has(e.from) && onPath.has(e.to);
                  const near = lit ? lit.has(e.from) && lit.has(e.to) && (e.from === focus || e.to === focus) : false;
                  const color = e.kind === "flow" ? FLOW[e.risk ?? "guarded"] : "#9fb0c4";
                  const opacity = onSim || near ? 0.95 : lit ? 0.06 : risky ? 0.7 : 0.22;
                  return (
                    <line key={`${e.from}>${e.to}>${e.kind}`} x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke={onSim ? "#ffe2a8" : color}
                      strokeOpacity={opacity} strokeWidth={onSim ? 2.4 : risky || near ? 1.4 : 1} vectorEffect="non-scaling-stroke"
                      strokeDasharray={e.risk === "unknown" ? "3 4" : risky && motionOk ? "6 6" : undefined}
                      className={risky && motionOk ? `v3-flow${e.risk === "open" ? " fast" : ""}` : undefined} />
                  );
                })}
                {pulse ? <circle cx={pulse.x} cy={pulse.y} r={5 / view.k} fill="#ffe2a8" /> : null}
                {map.nodes.filter((n) => visible.has(n.id)).map((n) => {
                  const p = layout.get(n.id)!;
                  const r = radiusOf(n);
                  const picked = n.id === selected;
                  const faded = lit !== null && !lit.has(n.id) && !onPath.has(n.id);
                  return (
                    <g
                      key={n.id}
                      className={`v3-map-node k-${n.kind}${picked ? " on" : ""}${onPath.has(n.id) ? " lit" : ""}${n.finding ? " finding" : ""}`}
                      role="button"
                      tabIndex={0}
                      aria-label={ariaLabel(n)}
                      aria-pressed={picked}
                      transform={`translate(${p.x} ${p.y})`}
                      opacity={faded ? 0.18 : 1}
                      onClick={() => select(n.id)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(n.id); }
                      }}
                      onPointerEnter={() => setFocus(n.id)}
                      onFocus={() => setFocus(n.id)}
                      onBlur={() => setFocus(null)}
                    >
                      <circle r={Math.max(r + 6, 12)} fill="transparent" />
                      {picked ? <circle r={r + 4} fill="none" stroke="#eef2f7" strokeOpacity={0.55} strokeWidth={1.5} vectorEffect="non-scaling-stroke" /> : null}
                      <Mark n={n} r={r} />
                      {shown.has(n.id) ? (
                        <text x={r + 4 / view.k} y={4 / view.k} fontSize={font / view.k}
                          className={`v3-graph-label${n.kind === "route" || n.kind === "helper" ? " mono" : ""}`}>
                          {labelText(n)}
                        </text>
                      ) : null}
                    </g>
                  );
                })}
              </g>
            </g>
          </svg>
        )}
        {!list ? (
          <div className="v3-map-controls">
            {motionOk ? <button type="button" aria-pressed={paused} onClick={() => setPaused((v) => !v)}>{paused ? "Play" : "Pause"}</button> : null}
            <button type="button" aria-label="Pan left" onClick={() => nudge(60, 0)}>←</button>
            <button type="button" aria-label="Pan right" onClick={() => nudge(-60, 0)}>→</button>
            <button type="button" aria-label="Zoom in" onClick={() => setView((v) => ({ ...v, k: Math.min(4, v.k * 1.25) }))}>+</button>
            <button type="button" aria-label="Zoom out" onClick={() => setView((v) => ({ ...v, k: Math.max(0.5, v.k / 1.25) }))}>−</button>
            <button type="button" aria-label="Reset view" onClick={() => setView(HOME)}>⟲</button>
          </div>
        ) : null}
      </div>

      <aside className="v3-map-side" aria-live="polite">
        {node && info ? (
          <>
            <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>{node.kind === "helper" ? "shared code" : node.kind === "control" ? "security check" : node.kind}</p>
            <p className="v3-map-title">{node.label}</p>
            <p style={{ color: info.tone, fontSize: 13 }}>{info.status}</p>
            <p className="v3-map-detail">{node.detail}</p>
            {node.file && node.kind === "route" && <p className="v3-map-file">{node.file}</p>}
            {info.action && <Link className="v3-btn v3-btn-sm v3-ondark" href={info.action.href}>{info.action.label}</Link>}
            {node.fact ? (
              <div className="v3-map-sim">
                <p className="v3-map-sim-hd">Simulate a request</p>
                <div className="v3-map-seg" role="group" aria-label="Who is calling">
                  <button type="button" aria-pressed={attacker === "anonymous"} onClick={() => { setAttacker("anonymous"); setSim(null); }}>No sign-in</button>
                  <button type="button" aria-pressed={attacker === "signed_in"} onClick={() => { setAttacker("signed_in"); setSim(null); }}>Any signed-in user</button>
                </div>
                <button type="button" className="v3-btn v3-btn-sm v3-ondark" onClick={run}>Send it</button>
                {sim && sim.routeId === node.id ? (
                  <ol className="v3-map-steps">
                    {sim.result.steps.slice(0, stepsShown).map((step) => <li key={step}>{step}</li>)}
                    {done ? <li style={{ color: OUTCOME[sim.result.outcome].tone }}><b>{OUTCOME[sim.result.outcome].label}</b></li> : null}
                  </ol>
                ) : null}
                <p className="v3-map-note">Simulated from what the audit read in your code. Not live traffic, and not a test of your app.</p>
              </div>
            ) : null}
          </>
        ) : <p className="v3-map-detail">Select a node.</p>}
        <ul className="v3-map-legend">
          {(["open", "unscoped", "unknown", "scoped", "secret", "none"] as Exposure[]).filter((k) => counts[k]).map((k) => (
            <li key={k}>
              <svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: k, kind: "route", label: "", detail: "", exposure: k }} r={4.5} /></svg>
              {EXPOSURE[k].label} <span className="v3-map-count">{counts[k]}</span>
            </li>
          ))}
          <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "c", kind: "control", label: "", detail: "" }} r={5} /></svg>Security check</li>
          <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "t", kind: "table", label: "", detail: "" }} r={4.5} /></svg>Table</li>
          <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "p", kind: "provider", label: "", detail: "", connection: "coming_soon" }} r={5} /></svg>Service</li>
          <li><svg width="14" height="12" viewBox="0 0 14 12" aria-hidden="true"><line x1="0" y1="6" x2="14" y2="6" stroke={OPEN} strokeWidth="2" /></svg>Exposed data flow</li>
        </ul>
        {map.truncated && <p className="v3-map-file">Showing the first {map.nodes.filter((n) => n.kind === "route").length} routes, findings first.</p>}
      </aside>
    </div>
  );
}
