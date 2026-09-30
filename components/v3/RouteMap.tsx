"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { MapNode, RouteMap as RouteMapData } from "@/lib/routeMap";

/**
 * Q27: the application as a rotating 3D graph of what the audit read. Plain
 * DOM and SVG with a perspective projection, no 3D library. Drag to orbit,
 * buttons to zoom, every node is a button (keyboard and screen readers).
 * Rotation pauses on interaction and never starts under reduced motion.
 */
type View = { yaw: number; pitch: number; zoom: number };

const REDUCED = "(prefers-reduced-motion: reduce)";
const subscribeMotion = (listener: () => void) => {
  const query = window.matchMedia(REDUCED);
  query.addEventListener("change", listener);
  return () => query.removeEventListener("change", listener);
};

const FILL: Record<string, string> = { route: "#4a6fa8", table: "#9fb0c4", provider: "#13243a" };

export function project(p: [number, number, number], view: View, cx: number, cy: number, scale: number) {
  const [x, y, z] = p;
  const cyw = Math.cos(view.yaw), syw = Math.sin(view.yaw), cp = Math.cos(view.pitch), sp = Math.sin(view.pitch);
  const x1 = x * cyw - z * syw, z1 = x * syw + z * cyw;
  const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
  const f = (900 / (900 + z2)) * view.zoom * scale;
  return { x: cx + x1 * f, y: cy + y2 * f, f, z: z2 };
}

function describe(node: MapNode): { status: string; tone: string; action?: { href: string; label: string } } {
  if (node.kind === "provider") {
    return node.connection === "available"
      ? { status: "Detected · live connection available", tone: "#7fc4a0", action: { href: "/dashboard/stack", label: "Connect read only" } }
      : { status: "Detected · live connection coming soon", tone: "#9fb0c4" };
  }
  if (node.kind === "table") return { status: "Table", tone: "#c3cfdd" };
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
  const [size, setSize] = useState({ w: 720, h: 460 });
  const [view, setView] = useState<View>({ yaw: 0.6, pitch: 0.42, zoom: 1 });
  // Motion is allowed only after hydration and only without reduced motion.
  const motionOk = useSyncExternalStore(subscribeMotion, () => !window.matchMedia(REDUCED).matches, () => false);
  const [stopped, setStopped] = useState(false);
  const spin = motionOk && !stopped;
  const [selected, setSelected] = useState<string>(() =>
    (map.nodes.find((n) => n.finding === "CRITICAL") ?? map.nodes.find((n) => n.finding) ?? map.nodes.find((n) => n.hot) ?? map.nodes[0])?.id ?? "");

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setSize({ w: entry.contentRect.width, h: entry.contentRect.width < 560 ? 360 : 460 }));
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

  // The layout fits a 240 radius; leave room for labels.
  const scale = Math.min(size.w, size.h) / 560;
  const projected = useMemo(() => new Map(map.nodes.map((n) => [n.id, project(n.p, view, size.w / 2, size.h / 2, scale)])), [map.nodes, view, size, scale]);
  const node = map.nodes.find((n) => n.id === selected);
  const info = node ? describe(node) : null;
  const touched = (a: string, b: string) => a === selected || b === selected;

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
            const on = touched(a, b);
            const depth = Math.max(0.18, Math.min(0.85, (p.f + q.f) / 2 - 0.45));
            return <line key={`${a}>${b}`} x1={p.x} y1={p.y} x2={q.x} y2={q.y}
              stroke={on ? `rgba(232,211,160,${depth + 0.1})` : `rgba(80,112,160,${depth * 0.45})`} strokeWidth={on ? 1.6 : 1} />;
          })}
        </svg>
        {[...map.nodes].sort((a, b) => projected.get(b.id)!.z - projected.get(a.id)!.z).map((n) => {
          const q = projected.get(n.id)!;
          const base = n.kind === "provider" ? 22 : n.kind === "table" ? 13 : n.hot || n.finding ? 17 : 11;
          const s = base * q.f;
          const picked = n.id === selected;
          const fill = n.hot ? "#c9a961" : n.finding === "CRITICAL" ? "#d9534a" : n.finding ? "#d98a3a" : FILL[n.kind];
          const label = picked || n.hot || n.finding || n.kind === "provider";
          return (
            <span key={n.id}>
              <button
                type="button"
                className={`v3-map-node${picked ? " on" : ""}${n.hot ? " hot" : ""}`}
                aria-label={`${n.kind} ${n.label}${n.finding ? `, open ${n.finding.toLowerCase()} finding` : ""}${n.hot ? ", heavy traffic" : ""}`}
                aria-pressed={picked}
                onClick={() => { setSelected(n.id); setStopped(true); }}
                style={{
                  left: q.x - s / 2, top: q.y - s / 2, width: s, height: s, background: fill,
                  borderRadius: n.kind === "table" ? 3 : n.kind === "provider" ? 6 : "50%",
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
          {motionOk && <button type="button" onClick={() => setStopped((v) => !v)}>{spin ? "Pause" : "Rotate"}</button>}
          <button type="button" aria-label="Zoom in" onClick={() => setView((v) => ({ ...v, zoom: Math.min(1.9, v.zoom + 0.15) }))}>+</button>
          <button type="button" aria-label="Zoom out" onClick={() => setView((v) => ({ ...v, zoom: Math.max(0.55, v.zoom - 0.15) }))}>−</button>
        </div>
      </div>

      <aside className="v3-map-side" aria-live="polite">
        {node && info ? (
          <>
            <p className="v3-eyebrow" style={{ color: "var(--muted-navy)" }}>{node.kind}</p>
            <p className="v3-map-title">{node.label}</p>
            <p style={{ color: info.tone, fontSize: 13 }}>{info.status}</p>
            <p className="v3-map-detail">{node.detail}</p>
            {node.file && <p className="v3-map-file">{node.file}</p>}
            {info.action && <Link className="v3-btn v3-btn-sm v3-ondark" href={info.action.href}>{info.action.label}</Link>}
          </>
        ) : <p className="v3-map-detail">Select a node.</p>}
        <ul className="v3-map-legend">
          <li><i style={{ background: "#4a6fa8", borderRadius: "50%" }} />Route</li>
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
