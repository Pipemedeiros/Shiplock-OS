"use client";

import { useEffect, useRef, useState } from "react";
import { cn } from "@/lib/utils";

// "Scroll Float" — reveals children once, the first time they enter the
// viewport. Deliberately not a scroll-linked animation (no parallax, no
// re-triggering on scroll-up) to keep the effect calm and predictable.
export function ScrollReveal({
  children,
  className,
  delayMs = 0,
}: {
  children: React.ReactNode;
  className?: string;
  delayMs?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setShown(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      data-reveal={shown ? "shown" : "hidden"}
      style={{ transitionDelay: shown ? `${delayMs}ms` : "0ms" }}
      className={cn(className)}
    >
      {children}
    </div>
  );
}
