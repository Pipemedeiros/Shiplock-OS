import type { ReactNode } from "react";

/** A card that shows its title and a one-line status, and opens on a click.
 * Native details/summary: keyboard and screen reader support for free. */
export function Fold({ title, status, open = false, children }: { title: string; status: ReactNode; open?: boolean; children: ReactNode }) {
  return (
    <details className="v3-card v3-fold" open={open}>
      <summary>
        <h2 className="v3-eyebrow">{title}</h2>
        <span className="v3-small">{status}</span>
      </summary>
      <div className="v3-card-p">{children}</div>
    </details>
  );
}
