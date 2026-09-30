"use client";

// ReactBits-style micro-interactions (CountUp, ShinyText, SpotlightCard,
// scroll Reveal, DecryptText, ProximityText, RevealList), reimplemented
// dependency-free for this exploration — the originals are copy-in
// components; these keep the branch clean of new packages. All respect
// prefers-reduced-motion. Deliberately doesn't include any of the
// library's decorative animated backgrounds (particles/threads/aurora
// style) — those read as generic SaaS-template and fight this brand's
// restrained porcelain/bronze positioning.

import { Children, useEffect, useRef, useState, useSyncExternalStore } from "react";

function reducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

// Hover capability is unknown during SSR and must match the server's
// render on first client paint to avoid a hydration mismatch —
// useSyncExternalStore handles that (server snapshot = false, real value
// only takes effect after hydration), unlike a plain useEffect+setState
// pair, which would cause an extra render pass for the same result.
const noopSubscribe = () => () => {};
function useHoverCapable(): boolean {
  return useSyncExternalStore(
    noopSubscribe,
    () => !reducedMotion() && window.matchMedia("(hover: hover)").matches,
    () => false
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

const SCRAMBLE_CHARS = "!<>-_\\/[]{}=+*^?#";

/** Scramble-then-resolve text reveal — thematically "verification
 * resolving," used sparingly. Server-rendered as the real, final text
 * (readable/indexable without JS); the scramble is a client-only overlay
 * on top that starts once the element is on screen, same trigger pattern
 * as Reveal. aria-label pins the accessible name to the real text so
 * assistive tech never announces the in-progress scramble. */
export function DecryptText({
  text,
  duration = 700,
  className = "",
}: {
  text: string;
  duration?: number;
  className?: string;
}) {
  const [display, setDisplay] = useState(text);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (reducedMotion()) return;
    const el = ref.current;
    if (!el) return;

    let cancelled = false;
    let frame = 0;

    function run() {
      const start = performance.now();
      const step = (now: number) => {
        if (cancelled) return;
        const t = Math.min(1, (now - start) / duration);
        const resolved = Math.floor(t * text.length);
        let out = "";
        for (let i = 0; i < text.length; i++) {
          if (text[i] === " " || i < resolved) {
            out += text[i];
          } else {
            out += SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
          }
        }
        setDisplay(out);
        if (t < 1) frame = requestAnimationFrame(step);
        else setDisplay(text);
      };
      frame = requestAnimationFrame(step);
    }

    if (el.getBoundingClientRect().top <= window.innerHeight - 60) {
      run();
      return () => {
        cancelled = true;
        cancelAnimationFrame(frame);
      };
    }
    const io = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          run();
          io.disconnect();
        }
      },
      { rootMargin: "0px 0px 100px 0px" }
    );
    io.observe(el);
    return () => {
      cancelled = true;
      io.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [text, duration]);

  return (
    <span ref={ref} className={className} aria-label={text}>
      {display}
    </span>
  );
}

/** Letters swell slightly as the pointer nears them — restrained,
 * editorial, not a particle effect. Server/SSR and touch/no-hover
 * devices get plain text; the letter-split, pointer-tracked version is a
 * client-only, hover-capable-only progressive enhancement. */
export function ProximityText({
  text,
  className = "",
  radius = 90,
}: {
  text: string;
  className?: string;
  radius?: number;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const enhanced = useHoverCapable();

  if (!enhanced) {
    return <span className={className}>{text}</span>;
  }

  return (
    <span
      ref={ref}
      className={`dxd-proximity ${className}`}
      onMouseMove={(e) => {
        ref.current?.querySelectorAll<HTMLElement>("[data-l]").forEach((el) => {
          const r = el.getBoundingClientRect();
          const d = Math.hypot(e.clientX - (r.left + r.width / 2), e.clientY - (r.top + r.height / 2));
          const t = Math.max(0, 1 - d / radius);
          el.style.setProperty("--sc", `${1 + t * 0.16}`);
        });
      }}
      onMouseLeave={() => {
        ref.current?.querySelectorAll<HTMLElement>("[data-l]").forEach((el) => {
          el.style.removeProperty("--sc");
        });
      }}
    >
      {/* Group letters by WORD so lines only break at spaces — a bare
          per-letter split lets the browser break mid-word ("protecti"/"ng"). */}
      {text.split(/(\s+)/).map((chunk, ci) =>
        /^\s+$/.test(chunk) ? (
          <span key={ci}> </span>
        ) : (
          <span key={ci} className="dxd-proximity-word">
            {[...chunk].map((ch, i) => (
              <span key={`${ci}-${i}`} data-l className="dxd-proximity-char">
                {ch}
              </span>
            ))}
          </span>
        )
      )}
    </span>
  );
}

/** Staggers each direct child through the existing Reveal, instead of
 * hand-wiring `delay={i * 90}` on individually-wrapped Reveals at every
 * call site. Reuses Reveal's own IntersectionObserver/reduced-motion
 * logic rather than duplicating it. */
export function RevealList({
  children,
  step = 90,
}: {
  children: React.ReactNode;
  step?: number;
}) {
  return (
    <>
      {Children.map(children, (child, i) => (
        <Reveal delay={i * step}>{child}</Reveal>
      ))}
    </>
  );
}
