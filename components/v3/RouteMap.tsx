"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import {
  simulateRequest, type Attacker, type Exposure, type MapEdge, type MapNode, type Risk, type RouteMap as RouteMapData, type Simulation,
} from "@/lib/routeMap";

/**
 * The application's security map (Q27; Felipe 2026-10-01: distinguishable,
 * more 3D, auth linking to the database, data flow). Routes are coloured by
 * what they expose; each passes the security controls the audit read on it
 * (sign-in, rows scoped to the caller, secret or signature) before its data
 * reaches tables and the database. Flows are coloured by risk and animated.
 * Plain DOM and SVG with a perspective projection, no 3D library. Drag to
 * orbit, buttons to zoom, every node a button.
 *
 * "Simulate a request" plays a request through a route from those facts; it
 * is labelled as a simulation, not live traffic.
 */
type View = { yaw: number; pitch: number; zoom: number };

const REDUCED = "(prefers-reduced-motion: reduce)";
const subscribeMotion = (listener: () => void) => {
  const query = window.matchMedia(REDUCED);
  query.addEventListener("change", listener);
  return () => query.removeEventListener("change", listener);
};

export const EXPOSURE: Record<Exposure, { color: string; label: string }> = {
  open: { color: "#ff7a59", label: "No sign-in, reaches data" },
  unscoped: { color: "#f2b84b", label: "Signed in, not limited to own rows" },
  unknown: { color: "#9aa5b4", label: "A check we could not read" },
  scoped: { color: "#5b8def", label: "Scoped to the caller" },
  secret: { color: "#a78bfa", label: "Secret or signature" },
  none: { color: "#3e4c63", label: "Reaches no table" },
};
const RISK: Record<Risk, string> = { open: "#ff7a59", unknown: "#9aa5b4", unscoped: "#f2b84b", guarded: "#4f7bd8" };
const KIND = { table: "#3fb6a8", control: "#c9a961", helper: "#6f84a6", provider: "#13243a" } as const;
const OUTCOME: Record<Simulation["outcome"], { label: string; tone: string }> = {
  stopped: { label: "Stopped", tone: "#9fd3b8" },
  scoped: { label: "Reaches only the caller's rows", tone: "#c3cfdd" },
  reaches: { label: "Reaches data it should not", tone: "#ff9d85" },
  unknown: { label: "Unknown: a check we could not read", tone: "#e8d3a0" },
};
const RISKY: Exposure[] = ["open", "unscoped", "unknown"];

export function project(p: [number, number, number], view: View, cx: number, cy: number, scale: number) {
  const [x, y, z] = p;
  const cyw = Math.cos(view.yaw), syw = Math.sin(view.yaw), cp = Math.cos(view.pitch), sp = Math.sin(view.pitch);
  const x1 = x * cyw - z * syw, z1 = x * syw + z * cyw;
  const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
  const f = (700 / (700 + z2)) * view.zoom * scale;
  return { x: cx + x1 * f, y: cy + y2 * f, f, z: z2 };
}

/**
 * The nodes a simulated request passes, in order, along the map's own edges:
 * the route, the controls it meets, then (if it gets through) the tables.
 * A stopped request ends at the control that stops it.
 */
export function simulationPath(map: RouteMapData, routeId: string, sim: Simulation): string[] {
  const out = (id: string, kind: MapEdge["kind"]) => map.edges.filter((e) => e.from === id && e.kind === kind).map((e) => e.to);
  const path = [routeId];
  let at = routeId;
  for (;;) {
    const next = out(at, "guard").find((id) => id.startsWith("control:"));
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
  if (node.kind === "table") return { status: "Table", tone: KIND.table };
  if (node.kind === "control") return { status: "Security control read in your code", tone: KIND.control };
  if (node.kind === "helper") return { status: "Shared code", tone: "#c3cfdd" };
  if (node.finding) {
    return { status: node.finding === "CRITICAL" ? "Open critical finding" : "Open finding", tone: node.finding === "CRITICAL" ? "#ff9d85" : "#f2b84b",
      action: { href: "/dashboard/risks", label: "Review the finding" } };
  }
  if (node.hot) return { status: "Heavy traffic observed", tone: "#e8d3a0", action: { href: "/dashboard/risks", label: "See the rate limit offer" } };
  const e = EXPOSURE[node.exposure ?? "none"];
  return { status: e.label, tone: e.color };
}

function fillOf(n: MapNode): string {
  if (n.kind === "route") return EXPOSURE[n.exposure ?? "none"].color;
  return KIND[n.kind];
}

export function RouteMap({ map }: { map: RouteMapData }) {
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; view: View } | null>(null);
  const [size, setSize] = useState({ w: 760, h: 540 });
  const [view, setView] = useState<View>({ yaw: 0.55, pitch: 0.5, zoom: 1 });
  const motionOk = useSyncExternalStore(subscribeMotion, () => !window.matchMedia(REDUCED).matches, () => false);
  const [stopped, setStopped] = useState(false);
  const [showShared, setShowShared] = useState(false);
  const [riskyOnly, setRiskyOnly] = useState(false);
  const [selected, setSelected] = useState<string>(() =>
    (map.nodes.find((n) => n.finding === "CRITICAL") ?? map.nodes.find((n) => n.finding) ?? map.nodes.find((n) => n.exposure === "open")
      ?? map.nodes.find((n) => n.exposure === "unscoped") ?? map.nodes.find((n) => n.id === "control:session")
      ?? map.nodes.find((n) => n.kind === "route") ?? map.nodes[0])?.id ?? "");
  const [attacker, setAttacker] = useState<Attacker>("anonymous");
  const [sim, setSim] = useState<{ routeId: string; result: Simulation; path: string[]; progress: number } | null>(null);
  const spin = motionOk && !stopped && !sim;

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setSize({ w: entry.contentRect.width, h: entry.contentRect.width < 560 ? 400 : 540 }));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!spin) return;
    let frame = 0;
    const tick = () => { setView((v) => ({ ...v, yaw: v.yaw + 0.0022 })); frame = requestAnimationFrame(tick); };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [spin]);

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

  // What is shown: shared code only when asked; "risky only" keeps exposed
  // routes and everything their data reaches.
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

  const scale = Math.min(size.w, size.h) / 560;
  const projected = useMemo(() => new Map(map.nodes.map((n) => [n.id, project(n.p, view, size.w / 2, size.h / 2 + 10, scale)])), [map.nodes, view, size, scale]);
  const zs = [...projected.values()].map((q) => q.z);
  const zMin = Math.min(...zs), zMax = Math.max(...zs);
  const depth = (z: number) => (zMax === zMin ? 1 : 1 - (z - zMin) / (zMax - zMin)); // 1 near, 0 far
  const node = map.nodes.find((n) => n.id === selected);
  const info = node ? describe(node) : null;
  const hops = sim ? sim.path.length - 1 : 0;
  const reachedIndex = sim ? Math.floor(sim.progress) : -1;
  const onPath = new Set(sim ? sim.path.slice(0, reachedIndex + 1) : []);
  const done = sim !== null && sim.progress >= hops;
  const touched = (e: MapEdge) => e.from === selected || e.to === selected;

  function run() {
    if (!node?.fact) return;
    const result = simulateRequest(node.fact, attacker);
    const path = simulationPath(map, node.id, result);
    setStopped(true);
    setSim({ routeId: node.id, result, path, progress: motionOk ? 0 : path.length - 1 });
  }

  let pulse: { x: number; y: number } | null = null;
  if (sim && !done) {
    const i = reachedIndex, t = sim.progress - i;
    const a = projected.get(sim.path[i]), b = projected.get(sim.path[i + 1]);
    if (a && b) pulse = { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
  }
  const stepsShown = sim ? (done ? sim.result.steps.length : Math.min(sim.result.steps.length - 1, reachedIndex + 1)) : 0;
  const counts = map.nodes.filter((n) => n.kind === "route").reduce<Record<string, number>>((acc, n) => {
    const k = n.exposure ?? "none"; acc[k] = (acc[k] ?? 0) + 1; return acc;
  }, {});

  return (
    <div className="v3-map">
      <div
        ref={box}
        className="v3-map-stage"
        style={{ height: size.h }}
        onPointerDown={(e) => { if ((e.target as HTMLElement).tagName === "BUTTON") return; setStopped(true); drag.current = { x: e.clientX, y: e.clientY, view }; (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId); }}
        onPointerMove={(e) => {
          const d = drag.current;
          if (!d) return;
          setView({ ...d.view, yaw: d.view.yaw + (e.clientX - d.x) / 180, pitch: Math.max(0.05, Math.min(1.25, d.view.pitch + (e.clientY - d.y) / 240)) });
        }}
        onPointerUp={() => { drag.current = null; }}
      >
        <svg className="v3-map-edges" width={size.w} height={size.h} aria-hidden="true">
          {map.edges.map((e) => {
            if (!visible.has(e.from) || !visible.has(e.to)) return null;
            const p = projected.get(e.from), q = projected.get(e.to);
            if (!p || !q) return null;
            const d = (depth(p.z) + depth(q.z)) / 2;
            const lit = onPath.has(e.from) && onPath.has(e.to);
            const sel = touched(e);
            const color = e.kind === "flow" ? RISK[e.risk ?? "guarded"] : e.kind === "guard" ? KIND.control : e.kind === "store" ? KIND.table : "#6f84a6";
            const weight = lit ? 2.6 : e.kind === "flow" && e.risk !== "guarded" ? 1.6 : sel ? 1.4 : 1;
            const alpha = lit || sel ? 0.95 : (e.kind === "flow" && e.risk !== "guarded" ? 0.75 : 0.28) * (0.45 + 0.55 * d);
            const animated = motionOk && e.kind === "flow" && e.risk !== "guarded";
            return <line key={`${e.from}>${e.to}>${e.kind}`} x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke={color} strokeOpacity={alpha}
              strokeWidth={weight} className={animated ? `v3-flow${e.risk === "open" ? " fast" : ""}` : undefined}
              strokeDasharray={e.risk === "unknown" ? "3 4" : animated ? "6 6" : undefined} />;
          })}
          {pulse ? <circle cx={pulse.x} cy={pulse.y} r={6} fill="#ffe2a8" /> : null}
        </svg>
        {[...map.nodes].filter((n) => visible.has(n.id)).sort((a, b) => projected.get(b.id)!.z - projected.get(a.id)!.z).map((n) => {
          const q = projected.get(n.id)!;
          const d = depth(q.z);
          const base = n.kind === "provider" ? 24 : n.kind === "control" ? 22 : n.kind === "table" ? 13 : n.kind === "helper" ? 10 : n.hot || n.finding ? 16 : 12;
          const s = base * q.f;
          const picked = n.id === selected;
          const lit = onPath.has(n.id);
          const fill = fillOf(n);
          const label = picked || lit || n.kind === "control" || n.kind === "provider" || n.finding || n.hot || (n.kind === "route" && n.exposure === "open");
          return (
            <span key={n.id}>
              <button
                type="button"
                className={`v3-map-node k-${n.kind}${picked ? " on" : ""}${lit ? " lit" : ""}${n.finding ? " finding" : ""}`}
                aria-label={`${n.kind === "helper" ? "shared code" : n.kind} ${n.label}${n.exposure ? `, ${EXPOSURE[n.exposure].label}` : ""}${n.finding ? `, open ${n.finding.toLowerCase()} finding` : ""}`}
                aria-pressed={picked}
                onClick={() => { setSelected(n.id); setStopped(true); setSim(null); }}
                style={{
                  left: q.x - s / 2, top: q.y - s / 2, width: s, height: s, background: fill,
                  borderRadius: n.kind === "table" ? 3 : n.kind === "provider" ? 7 : n.kind === "control" ? 5 : n.kind === "helper" ? 2 : "50%",
                  transform: n.kind === "helper" || n.kind === "control" ? "rotate(45deg)" : undefined,
                  border: n.kind === "provider" ? (n.connection === "available" ? "1.5px solid #7fc4a0" : "1.5px dashed #6f839d") : 0,
                  opacity: 0.35 + 0.65 * d,
                  boxShadow: d > 0.55 ? `0 0 ${Math.round(8 + 10 * d)}px ${fill}66` : undefined,
                }}
              />
              {label && (
                <span className="v3-map-label" style={{ left: q.x + s / 2 + 6, top: q.y - 8, fontSize: 11 * Math.min(1.2, q.f), opacity: 0.5 + 0.5 * d,
                  color: n.kind === "control" ? "#e8d3a0" : n.kind === "route" ? "#dfe6ef" : "#c3cfdd" }}>
                  {n.label}{n.kind === "provider" && n.connection === "coming_soon" ? " · coming soon" : ""}
                </span>
              )}
            </span>
          );
        })}
        <div className="v3-map-toolbar" role="group" aria-label="Map view">
          <button type="button" aria-pressed={riskyOnly} onClick={() => setRiskyOnly((v) => !v)}>Only exposed paths</button>
          <button type="button" aria-pressed={showShared} onClick={() => setShowShared((v) => !v)}>Shared code</button>
        </div>
        <div className="v3-map-controls">
          {motionOk && <button type="button" onClick={() => { setSim(null); setStopped((v) => !v); }}>{spin ? "Pause" : "Rotate"}</button>}
          <button type="button" aria-label="Zoom in" onClick={() => setView((v) => ({ ...v, zoom: Math.min(1.9, v.zoom + 0.15) }))}>+</button>
          <button type="button" aria-label="Zoom out" onClick={() => setView((v) => ({ ...v, zoom: Math.max(0.55, v.zoom - 0.15) }))}>−</button>
        </div>
      </div>

      <aside className="v3-map-side" aria-live="polite">
        {node && info ? (
          <>
            <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>{node.kind === "helper" ? "shared code" : node.kind === "control" ? "security control" : node.kind}</p>
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
          {(Object.keys(EXPOSURE) as Exposure[]).filter((k) => counts[k]).map((k) => (
            <li key={k}><i style={{ background: EXPOSURE[k].color, borderRadius: "50%" }} />{EXPOSURE[k].label} <span className="v3-map-count">{counts[k]}</span></li>
          ))}
          <li><i style={{ background: KIND.control, transform: "rotate(45deg)", borderRadius: 2 }} />Security control</li>
          <li><i style={{ background: KIND.table, borderRadius: 2 }} />Table</li>
          <li><i style={{ background: KIND.provider, border: "1.5px solid #7fc4a0", borderRadius: 3 }} />Provider</li>
          <li><i style={{ background: RISK.open, height: 2, width: 14 }} />Exposed data flow</li>
        </ul>
        {map.truncated && <p className="v3-map-file">Showing the first {map.nodes.filter((n) => n.kind === "route").length} routes, findings first.</p>}
      </aside>
    </div>
  );
}
