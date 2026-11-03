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
const EXPOSURE: Record<Exposure, { color: string; label: string }> = {
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
// Felipe 2026-10-07: the map shows only what is wrong, red or yellow.
const LEVEL = { red: { color: OPEN, label: "Confirmed issue", aria: "confirmed issue" },
  yellow: { color: UNSCOPED, label: "Candidate or open way to data", aria: "candidate" } } as const;

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
  if (node.kind === "source") return { status: "Flagged traffic source", tone: "#ff9d85", action: { href: "/dashboard/traffic", label: "See its requests" } };
  if (node.level === "red") return { status: "Confirmed issue", tone: "#ff9d85", action: { href: "/dashboard/risks", label: "Review the issue" } };
  if (node.finding) return { status: "Candidate to review", tone: UNSCOPED, action: { href: "/dashboard/risks", label: "Review the candidate" } };
  if (node.attacked) return { status: "Attacked, nothing wrong read in the code", tone: HOT, action: { href: "/dashboard/traffic", label: "See who attacked it" } };
  if (node.hot) return { status: "Heavy traffic observed", tone: HOT, action: { href: "/dashboard/risks", label: "See the rate limit offer" } };
  const e = EXPOSURE[node.exposure ?? "none"];
  return { status: e.label, tone: e.color === DIM ? "#9fb0c4" : e.color };
}

const kindName = (n: MapNode) => n.kind === "helper" ? "shared code" : n.kind === "control" ? "security check" : n.kind === "source" ? "traffic source" : n.kind;
const ariaLabel = (n: MapNode) =>
  `${kindName(n)} ${n.label}`
  + `${n.exposure ? `, ${EXPOSURE[n.exposure].label}` : ""}${n.level ? `, ${LEVEL[n.level].aria}` : ""}${n.attacked ? ", attacked" : ""}`;
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
  if (n.kind === "source") {
    return <path d={`M0 ${-r} L${r * 0.95} ${r * 0.75} L${-r * 0.95} ${r * 0.75} Z`} fill="#0f1b2d" stroke={OPEN} strokeWidth={1.8} vectorEffect="non-scaling-stroke" />;
  }
  // A route is red (confirmed) or yellow (candidate, open exposure); a
  // confirmed one also wears a ring, so degree is never colour alone.
  const color = n.level ? LEVEL[n.level].color : QUIET;
  return (
    <>
      {n.level === "red" ? <circle r={r + 5} fill="none" stroke={color} strokeOpacity={0.5} strokeWidth={1.4} vectorEffect="non-scaling-stroke" /> : null}
      {n.attacked ? <circle r={r + 3} fill="none" stroke={OPEN} strokeOpacity={0.8} strokeDasharray="1.5 2.5" strokeWidth={1.2} vectorEffect="non-scaling-stroke" /> : null}
      {n.hot ? <circle r={r + 8} fill="none" stroke={HOT} strokeDasharray="2 3" strokeWidth={1} vectorEffect="non-scaling-stroke" /> : null}
      <circle r={r} fill={color} />
    </>
  );
}

/** The same facts as text: wrong routes by degree, red first, with what each reaches. */
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
  const sources = map.nodes.filter((n) => n.kind === "source" && visible.has(n.id));
  const label = (id: string) => map.nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <div className="v3-graph-list">
      {sources.length ? (
        <section>
          <h3><i style={{ background: OPEN }} />Traffic sources <b>{sources.length}</b></h3>
          <ul>
            {sources.map((n) => (
              <li key={n.id}>
                <button type="button" aria-pressed={n.id === selected} onClick={() => onSelect(n.id)}>{n.label}</button>
                <span>hit {map.edges.filter((e) => e.from === n.id && e.kind === "attack").map((e) => label(e.to)).join(", ")} · {n.detail}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      {(["red", "yellow"] as const).map((g) => {
        const rows = routes.filter((n) => n.level === g);
        if (rows.length === 0) return null;
        return (
          <section key={g}>
            <h3><i style={{ background: LEVEL[g].color }} />{LEVEL[g].label} <b>{rows.length}</b></h3>
            <ul>
              {rows.map((n) => {
                const t = reaches(n.id);
                return (
                  <li key={n.id}>
                    <button type="button" aria-pressed={n.id === selected} onClick={() => onSelect(n.id)}>{n.label}</button>
                    <span>{t.length ? `reaches ${t.join(", ")}` : "reaches no table"}{n.exposure ? ` · ${EXPOSURE[n.exposure].label}` : ""}</span>
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
  const [list, setList] = useState(false);
  const [selected, setSelected] = useState<string>(() =>
    (map.nodes.find((n) => n.level === "red") ?? map.nodes.find((n) => n.level === "yellow") ?? map.nodes.find((n) => n.kind === "source"))?.id ?? "");
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
  const radiusOf = (n: MapNode) => n.kind === "provider" ? 11 : n.kind === "control" ? 9 : n.kind === "source" ? 8 : n.kind === "helper" ? 3
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

  // What is shown: only the routes that are wrong, and everything their
  // requests reach; shared code they run only when asked.
  const visible = useMemo(() => {
    const wrong = map.nodes.filter((n) => n.kind === "route" && (n.level || n.attacked)).map((n) => n.id);
    const keep = new Set<string>([...wrong, ...map.nodes.filter((n) => n.kind === "source").map((n) => n.id)]);
    for (let changed = true; changed;) {
      changed = false;
      for (const e of map.edges) if (keep.has(e.from) && !keep.has(e.to) && e.kind !== "shared") { keep.add(e.to); changed = true; }
    }
    if (showShared) for (const e of map.edges) if (e.kind === "shared" && wrong.includes(e.from)) keep.add(e.to);
    return keep;
  }, [map, showShared]);

  // The lit neighbourhood: the hovered or focused node and everything one edge away.
  const lit = useMemo(() => {
    if (!focus) return null;
    const s = new Set([focus]);
    for (const e of map.edges) { if (e.from === focus) s.add(e.to); if (e.to === focus) s.add(e.from); }
    return s;
  }, [focus, map.edges]);

  // Frame what is drawn. The layout keeps every node's place (so a filter
  // never reshuffles it), which leaves the drawn subset small in the middle;
  // this fits its bounds to the stage, under the reader's own pan and zoom.
  const fit = useMemo(() => {
    const points = [...visible].map((id) => layout.get(id)).filter((p): p is { x: number; y: number } => Boolean(p));
    if (points.length < 2) return HOME;
    const xs = points.map((p) => p.x), ys = points.map((p) => p.y);
    const [x0, x1, y0, y1] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    // Room on the right for labels, which sit to the right of their node.
    const k = Math.max(0.6, Math.min(2.4, (2 * BOX * stage.aspect * 0.7) / Math.max(x1 - x0, 1), (2 * BOX * 0.78) / Math.max(y1 - y0, 1)));
    return { x: -((x0 + x1) / 2) * k - BOX * stage.aspect * 0.08, y: -((y0 + y1) / 2) * k, k };
  }, [visible, layout, stage.aspect]);
  const K = view.k * fit.k;
  const tx = view.k * fit.x + view.x, ty = view.k * fit.y + view.y;

  const node = map.nodes.find((n) => n.id === selected);
  const info = node ? describe(node) : null;
  const hops = sim ? sim.path.length - 1 : 0;
  const reachedIndex = sim ? Math.floor(sim.progress) : -1;
  const onPath = new Set(sim ? sim.path.slice(0, reachedIndex + 1) : []);
  const done = sim !== null && sim.progress >= hops;
  const stepsShown = sim ? (done ? sim.result.steps.length : Math.min(sim.result.steps.length - 1, reachedIndex + 1)) : 0;
  const drifting = motionOk && !paused && !focus && !sim && !dragging;
  const levels = { red: map.nodes.filter((n) => n.level === "red").length, yellow: map.nodes.filter((n) => n.level === "yellow").length };
  const sourceCount = map.nodes.filter((n) => n.kind === "source").length;

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
  // as you zoom in, or when lit. Placed in screen space so they never collide,
  // and sized to 12 screen pixels whatever the stage scale.
  const font = (12 * 2 * BOX) / stage.height;
  const marks = map.nodes.filter((n) => visible.has(n.id)).map((n) => {
    const p = layout.get(n.id)!, r = radiusOf(n) * K;
    return { x: p.x * K - r, y: p.y * K - r, w: 2 * r, h: 2 * r };
  });
  const shown = placeLabels(map.nodes.filter((n) => visible.has(n.id)).map((n) => {
    const p = layout.get(n.id)!;
    const important = n.kind !== "route" && n.kind !== "helper" || Boolean(n.finding) || Boolean(n.hot) || Boolean(n.attacked);
    const force = n.id === selected || onPath.has(n.id) || n.id === focus;
    const wanted = important || view.k >= 1.8 || (lit?.has(n.id) ?? false);
    const r = radiusOf(n);
    const w = labelText(n).length * font * 0.6 + 4;
    return { id: n.id, x: (p.x * K) + r * K + 4, leftX: (p.x * K) - r * K - 4 - w, y: (p.y * K) - font / 2, w, h: font + 4,
      priority: wanted ? (n.kind === "control" ? 6 : n.kind === "source" ? 5 : n.finding ? 5 : n.kind === "provider" ? 4 : n.hot ? 3 : lit?.has(n.id) ? 2 : 1) : -1, force };
  }).filter((b) => b.force || b.priority >= 0), marks);

  function nudge(dx: number, dy: number) { setView((v) => ({ ...v, x: v.x + dx, y: v.y + dy })); }

  if (levels.red + levels.yellow + sourceCount === 0) {
    return (
      <div className="v3-map v3-map-quiet">
        <div className="v3-card-p" style={{ color: "#eef2f7" }}>
          <p>No route with an issue or an open way to data in this audit.</p>
          <p className="v3-map-note" style={{ marginTop: 6 }}>Routes we could not read are listed on <Link href="/dashboard/coverage" style={{ color: "#eef2f7", textDecoration: "underline" }}>Coverage</Link>.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="v3-map">
      <div className="v3-map-stage">
        <div className="v3-map-toolbar" role="group" aria-label="Map view">
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
            aria-label={`Map of ${levels.red} routes with a confirmed issue and ${levels.yellow} candidates or open ways to data${sourceCount ? `, and ${sourceCount} flagged traffic ${sourceCount === 1 ? "source" : "sources"}` : ""}. Use the List view for the same facts as text.`}
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
              <g transform={`translate(${tx} ${ty}) scale(${K})`}>
                {map.edges.map((e) => {
                  if (!visible.has(e.from) || !visible.has(e.to)) return null;
                  const p = layout.get(e.from), q = layout.get(e.to);
                  if (!p || !q) return null;
                  const risky = e.kind === "flow" && e.risk !== "guarded";
                  const onSim = onPath.has(e.from) && onPath.has(e.to);
                  const near = lit ? lit.has(e.from) && lit.has(e.to) && (e.from === focus || e.to === focus) : false;
                  const attack = e.kind === "attack";
                  const color = e.kind === "flow" ? FLOW[e.risk ?? "guarded"] : attack ? OPEN : "#9fb0c4";
                  const opacity = onSim || near ? 0.95 : lit ? 0.06 : risky || attack ? 0.7 : 0.22;
                  return (
                    <line key={`${e.from}>${e.to}>${e.kind}`} data-edge={e.kind} x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke={onSim ? "#ffe2a8" : color}
                      strokeOpacity={opacity} strokeWidth={onSim ? 2.4 : risky || near ? 1.4 : 1} vectorEffect="non-scaling-stroke"
                      strokeDasharray={attack ? "2 4" : e.risk === "unknown" ? "3 4" : risky && motionOk ? "6 6" : undefined}
                      className={risky && motionOk ? `v3-flow${e.risk === "open" ? " fast" : ""}` : undefined} />
                  );
                })}
                {pulse ? <circle cx={pulse.x} cy={pulse.y} r={5 / K} fill="#ffe2a8" /> : null}
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
                        <text x={shown.get(n.id) === "left" ? -(r + 4 / K) : r + 4 / K} y={font / 3 / K} fontSize={font / K}
                          textAnchor={shown.get(n.id) === "left" ? "end" : undefined}
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
            <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>{kindName(node)}</p>
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
          {(["red", "yellow"] as const).filter((k) => levels[k]).map((k) => (
            <li key={k}>
              <svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: k, kind: "route", label: "", detail: "", level: k }} r={4} /></svg>
              {LEVEL[k].label} <span className="v3-map-count">{levels[k]}</span>
            </li>
          ))}
          <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "c", kind: "control", label: "", detail: "" }} r={5} /></svg>Security check</li>
          <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "t", kind: "table", label: "", detail: "" }} r={4.5} /></svg>Table</li>
          <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "p", kind: "provider", label: "", detail: "", connection: "coming_soon" }} r={5} /></svg>Service</li>
          <li><svg width="14" height="12" viewBox="0 0 14 12" aria-hidden="true"><line x1="0" y1="6" x2="14" y2="6" stroke={OPEN} strokeWidth="2" /></svg>Exposed data flow</li>
          {sourceCount ? (
            <>
              <li><svg width="12" height="12" viewBox="-6 -6 12 12" aria-hidden="true"><Mark n={{ id: "s", kind: "source", label: "", detail: "" }} r={5} /></svg>Traffic source <span className="v3-map-count">{sourceCount}</span></li>
              <li><svg width="14" height="12" viewBox="0 0 14 12" aria-hidden="true"><line x1="0" y1="6" x2="14" y2="6" stroke={OPEN} strokeWidth="2" strokeDasharray="2 3" /></svg>Attack request</li>
            </>
          ) : null}
        </ul>
        {map.truncated && <p className="v3-map-file">Showing the first {map.nodes.filter((n) => n.kind === "route").length} routes, findings first.</p>}
      </aside>
    </div>
  );
}
