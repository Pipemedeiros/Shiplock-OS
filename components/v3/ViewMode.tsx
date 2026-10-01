"use client";

import { useState } from "react";

export type View = "plain" | "engineer";
export const VIEW_COOKIE = "sl_view";

function apply(view: View) {
  document.querySelector<HTMLElement>(".v3")?.setAttribute("data-view", view);
  document.cookie = `${VIEW_COOKIE}=${view}; path=/; max-age=31536000; samesite=lax`;
}

/** Plain words or engineer detail, the same facts either way. Switching is
 * instant (a data attribute the stylesheet reads); the cookie makes the next
 * page load render the chosen view on the server. */
export function ViewMode({ initial }: { initial: View }) {
  const [view, setView] = useState<View>(initial);
  const pick = (next: View) => {
    setView(next);
    apply(next);
  };
  return (
    <div className="v3-viewmode" role="group" aria-label="How much detail">
      {(["plain", "engineer"] as const).map((v) => (
        <button key={v} type="button" aria-pressed={view === v} onClick={() => pick(v)}>
          {v === "plain" ? "Plain" : "Engineer"}
        </button>
      ))}
    </div>
  );
}
