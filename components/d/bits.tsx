"use client";

// ReactBits-style micro-interactions (CountUp, ShinyText, SpotlightCard,
// scroll Reveal), reimplemented dependency-free for this exploration —
// the originals are copy-in components; these keep the branch clean of
// new packages. All respect prefers-reduced-motion.

import { useEffect, useRef, useState } from "react";

function reducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/** Animated number — eases to `to` whenever it changes. */
export function CountUp({
  to,
  duration = 1100,
}: {
  to: number;
  duration?: number;
}) {
  const [value, setValue] = useState(to);
  const prev = useRef(to);
  const raf = useRef<number>(0);

  useEffect(() => {
    const from = prev.current;
    prev.current = to;
    if (from === to || reducedMotion()) {
      setValue(to);
      return;
    }
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setValue(Math.round(from + (to - from) * eased));
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [to, duration]);

  return <>{value.toLocaleString()}</>;
}

/** Slow sheen across text — for one bronze moment, not everywhere. */
export function ShinyText({ children }: { children: React.ReactNode }) {
  return <span className="dxd-shiny">{children}</span>;
}

/** Card with a pointer-following bronze spotlight. */
export function SpotlightCard({
  className = "",
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  return (
    <div
      ref={ref}
      className={`dxd-spot ${className}`}
      onMouseMove={(e) => {
        const el = ref.current;
        if (!el) return;
        const r = el.getBoundingClientRect();
        el.style.setProperty("--sx", `${e.clientX - r.left}px`);
        el.style.setProperty("--sy", `${e.clientY - r.top}px`);
      }}
    >
      {children}
    </div>
  );
}

/** Fade-rise on first scroll into view — strictly progressive
 * enhancement. The server render is FULLY VISIBLE; hiding is only
 * applied client-side, after mount, when JS is provably running and the
 * element is below the fold. No JS, broken JS, stale tab: everything
 * still shows. */
export function Reveal({
  children,
  delay = 0,
}: {
  children: React.ReactNode;
  delay?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (reducedMotion()) return;
    // already on screen (or close): leave it visible, no animation
    if (el.getBoundingClientRect().top <= window.innerHeight - 60) return;

    el.classList.add("dxd-reveal-wait");
    const show = () => el.classList.remove("dxd-reveal-wait");
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          show();
          io.disconnect();
        }
      },
      { rootMargin: "0px 0px 100px 0px" }
    );
    io.observe(el);
    const failsafe = setTimeout(show, 4000);
    return () => {
      io.disconnect();
      clearTimeout(failsafe);
      show();
    };
  }, []);

  return (
    <div
      ref={ref}
      className="dxd-reveal"
      style={delay ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  );
}
