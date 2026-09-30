"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { simulateRequest, type Attacker, type MapNode, type RouteMap as RouteMapData, type Simulation } from "@/lib/routeMap";

/**
 * Q27: the application as a rotating 3D graph of what the audit read: routes,
 * the shared code that connects them, the tables they reach, and the
 * providers behind them. Plain DOM and SVG with a perspective projection, no
 * 3D library. Drag to orbit, buttons to zoom, every node a button.
 *
 * "Simulate a request" (Felipe 2026-09-30) plays a request through a route
 * from the audit's facts: who is calling, which shared code it runs, and
 * whether it is stopped, scoped, reaches data, or is unknown. It is a
 * simulation of what the code does, labelled as such; not live traffic.
 */
type View = { yaw: number; pitch: number; zoom: number };

const REDUCED = "(prefers-reduced-motion: reduce)";
const subscribeMotion = (listener: () => void) => {
  const query = window.matchMedia(REDUCED);
  query.addEventListener("change", listener);
  return () => query.removeEventListener("change", listener);
};

const FILL: Record<MapNode["kind"], string> = { route: "#4a6fa8", table: "#9fb0c4", provider: "#13243a", helper: "#6f84a6" };
const OUTCOME: Record<Simulation["outcome"], { label: string; tone: string }> = {
  stopped: { label: "Stopped", tone: "#9fd3b8" },
  scoped: { label: "Reaches only the caller's rows", tone: "#c3cfdd" },
  reaches: { label: "Reaches data it should not", tone: "#f0a09a" },
  unknown: { label: "Unknown: a check we could not read", tone: "#e8d3a0" },
};

export function project(p: [number, number, number], view: View, cx: number, cy: number, scale: number) {
  const [x, y, z] = p;
  const cyw = Math.cos(view.yaw), syw = Math.sin(view.yaw), cp = Math.cos(view.pitch), sp = Math.sin(view.pitch);
  const x1 = x * cyw - z * syw, z1 = x * syw + z * cyw;
  const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
  const f = (900 / (900 + z2)) * view.zoom * scale;
  return { x: cx + x1 * f, y: cy + y2 * f, f, z: z2 };
}

/** The nodes a simulated request passes through, in order, from the map's own edges. */
export function simulationPath(map: RouteMapData, routeId: string, sim: Simulation): string[] {
  const out = new Set(map.edges.filter(([a]) => a === routeId).map(([, b]) => b));
  const helpers = [...out].filter((id) => id.startsWith("helper:"));
  const tables = sim.outcome === "reaches" || sim.outcome === "scoped" ? sim.reached.map((t) => `table:${t}`).filter((id) => out.has(id)) : [];
  return [routeId, ...helpers, ...tables];
}

function describe(node: MapNode): { status: string; tone: string; action?: { href: string; label: string } } {
  if (node.kind === "provider") {
    return node.connection === "available"
      ? { status: "Detected · live connection available", tone: "#7fc4a0", action: { href: "/dashboard/stack", label: "Connect read only" } }
      : { status: "Detected · live connection coming soon", tone: "#9fb0c4" };
  }
  if (node.kind === "table") return { status: "Table", tone: "#c3cfdd" };
  if (node.kind === "helper") return { status: "Shared code", tone: "#c3cfdd" };
  if (node.finding) {
    return { status: node.finding === "CRITICAL" ? "Open critical finding" : "Open finding", tone: node.finding === "CRITICAL" ? "#f0a09a" : "#f0bd84",
      action: { href: "/dashboard/risks", label: "Review the finding" } };
  }
  if (node.hot) return { status: "Heavy traffic observed", tone: "#e8d3a0", action: { href: "/dashboard/risks", label: "See the rate limit offer" } };
  return { status: "Route read by the audit", tone: "#9fb3cc" };
}

export function RouteMap({ map }: { map: RouteMapData }) {
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; view: View } | null>(null);
  const [size, setSize] = useState({ w: 760, h: 520 });
  const [view, setView] = useState<View>({ yaw: 0.6, pitch: 0.42, zoom: 1 });
  const motionOk = useSyncExternalStore(subscribeMotion, () => !window.matchMedia(REDUCED).matches, () => false);
  const [stopped, setStopped] = useState(false);
  const [selected, setSelected] = useState<string>(() =>
    (map.nodes.find((n) => n.finding === "CRITICAL") ?? map.nodes.find((n) => n.finding) ?? map.nodes.find((n) => n.hot)
      ?? map.nodes.find((n) => n.kind === "route") ?? map.nodes[0])?.id ?? "");
  const [attacker, setAttacker] = useState<Attacker>("anonymous");
  const [sim, setSim] = useState<{ routeId: string; result: Simulation; path: string[]; progress: number } | null>(null);
  const spin = motionOk && !stopped && !sim;

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setSize({ w: entry.contentRect.width, h: entry.contentRect.width < 560 ? 380 : 520 }));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!spin) return;
    let frame = 0;
    const tick = () => { setView((v) => ({ ...v, yaw: v.yaw + 0.0025 })); frame = requestAnimationFrame(tick); };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [spin]);

  // The pulse moves one hop every 700 ms; progress counts hops completed.
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

  const scale = Math.min(size.w, size.h) / 560;
  const projected = useMemo(() => new Map(map.nodes.map((n) => [n.id, project(n.p, view, size.w / 2, size.h / 2, scale)])), [map.nodes, view, size, scale]);
  const node = map.nodes.find((n) => n.id === selected);
  const info = node ? describe(node) : null;
  const hops = sim ? sim.path.length - 1 : 0;
  const reachedIndex = sim ? Math.floor(sim.progress) : -1;
  const onPath = new Set(sim ? sim.path.slice(0, reachedIndex + 1) : []);
  const pathEdge = (a: string, b: string) => onPath.has(a) && onPath.has(b);
  const touched = (a: string, b: string) => a === selected || b === selected;
  const done = sim !== null && sim.progress >= hops;

  function run() {
    if (!node?.fact) return;
    const result = simulateRequest(node.fact, attacker);
    const path = simulationPath(map, node.id, result);
    setStopped(true);
    setSim({ routeId: node.id, result, path, progress: motionOk ? 0 : path.length - 1 });
  }

  // Where the pulse is: between path[i] and path[i + 1].
  let pulse: { x: number; y: number } | null = null;
  if (sim && !done) {
    const i = reachedIndex, t = sim.progress - i;
    const a = projected.get(sim.path[i]), b = projected.get(sim.path[i + 1]);
    if (a && b) pulse = { x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t };
  }
  const stepsShown = sim ? (done ? sim.result.steps.length : Math.min(sim.result.steps.length - 1, reachedIndex + 1)) : 0;

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
          setView({ ...d.view, yaw: d.view.yaw + (e.clientX - d.x) / 180, pitch: Math.max(0.05, Math.min(1.2, d.view.pitch + (e.clientY - d.y) / 240)) });
        }}
        onPointerUp={() => { drag.current = null; }}
      >
        <svg className="v3-map-edges" width={size.w} height={size.h} aria-hidden="true">
          {map.edges.map(([a, b]) => {
            const p = projected.get(a), q = projected.get(b);
            if (!p || !q) return null;
            const depth = Math.max(0.18, Math.min(0.85, (p.f + q.f) / 2 - 0.45));
            const lit = pathEdge(a, b);
            const on = touched(a, b);
            const stroke = lit ? (sim?.result.outcome === "reaches" ? "#f0a09a" : "#e8d3a0")
              : on ? `rgba(232,211,160,${depth + 0.1})` : `rgba(80,112,160,${depth * 0.45})`;
            return <line key={`${a}>${b}`} x1={p.x} y1={p.y} x2={q.x} y2={q.y} stroke={stroke} strokeWidth={lit ? 2.4 : on ? 1.6 : 1} />;
          })}
          {pulse ? <circle cx={pulse.x} cy={pulse.y} r={6} fill="#e8d3a0" /> : null}
        </svg>
        {[...map.nodes].sort((a, b) => projected.get(b.id)!.z - projected.get(a.id)!.z).map((n) => {
          const q = projected.get(n.id)!;
          const base = n.kind === "provider" ? 22 : n.kind === "table" ? 13 : n.kind === "helper" ? 12 : n.hot || n.finding ? 17 : 11;
          const s = base * q.f;
          const picked = n.id === selected;
          const lit = onPath.has(n.id);
          const fill = n.hot ? "#c9a961" : n.finding === "CRITICAL" ? "#d9534a" : n.finding ? "#d98a3a" : FILL[n.kind];
          const label = picked || lit || n.hot || n.finding || n.kind === "provider";
          return (
            <span key={n.id}>
              <button
                type="button"
                className={`v3-map-node${picked ? " on" : ""}${lit ? " lit" : ""}`}
                aria-label={`${n.kind === "helper" ? "shared code" : n.kind} ${n.label}${n.finding ? `, open ${n.finding.toLowerCase()} finding` : ""}${n.hot ? ", heavy traffic" : ""}`}
                aria-pressed={picked}
                onClick={() => { setSelected(n.id); setStopped(true); setSim(null); }}
                style={{
                  left: q.x - s / 2, top: q.y - s / 2, width: s, height: s, background: fill,
                  borderRadius: n.kind === "table" ? 3 : n.kind === "provider" ? 6 : n.kind === "helper" ? 2 : "50%",
                  transform: n.kind === "helper" ? "rotate(45deg)" : undefined,
                  border: n.kind === "provider" ? (n.connection === "available" ? "1.5px solid #7fc4a0" : "1.5px dashed #6f839d") : 0,
                  opacity: Math.max(0.45, Math.min(1, q.f - 0.15)),
                }}
              />
              {label && (
                <span className="v3-map-label" style={{ left: q.x + s / 2 + 6, top: q.y - 8, fontSize: 11 * Math.min(1.15, q.f) }}>
                  {n.label}{n.kind === "provider" && n.connection === "coming_soon" ? " · coming soon" : ""}
                </span>
              )}
            </span>
          );
        })}
        <div className="v3-map-controls">
          {motionOk && <button type="button" onClick={() => { setSim(null); setStopped((v) => !v); }}>{spin ? "Pause" : "Rotate"}</button>}
          <button type="button" aria-label="Zoom in" onClick={() => setView((v) => ({ ...v, zoom: Math.min(1.9, v.zoom + 0.15) }))}>+</button>
          <button type="button" aria-label="Zoom out" onClick={() => setView((v) => ({ ...v, zoom: Math.max(0.55, v.zoom - 0.15) }))}>−</button>
        </div>
      </div>

      <aside className="v3-map-side" aria-live="polite">
        {node && info ? (
          <>
            <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>{node.kind === "helper" ? "shared code" : node.kind}</p>
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
          <li><i style={{ background: "#4a6fa8", borderRadius: "50%" }} />Route</li>
          <li><i style={{ background: "#6f84a6", transform: "rotate(45deg)" }} />Shared code</li>
          <li><i style={{ background: "#9fb0c4", borderRadius: 2 }} />Table</li>
          <li><i style={{ background: "#13243a", border: "1.5px solid #7fc4a0", borderRadius: 3 }} />Provider</li>
          <li><i style={{ background: "#d98a3a", borderRadius: "50%" }} />Open finding</li>
          <li><i style={{ background: "#c9a961", borderRadius: "50%" }} />Heavy traffic</li>
        </ul>
        {map.truncated && <p className="v3-map-file">Showing the first {map.nodes.filter((n) => n.kind === "route").length} routes, findings first.</p>}
      </aside>
    </div>
  );
}
