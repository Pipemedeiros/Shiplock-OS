"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useProto } from "../store";
import { Mark } from "../ui";

const NAV = [
  { href: "/proto/app", label: "Overview" },
  { href: "/proto/app/paths", label: "Attack paths", badge: true },
  { href: "/proto/app/prs", label: "Pull requests" },
  { href: "/proto/app/runs", label: "Audit runs" },
  { href: "/proto/app/stack", label: "Your stack" },
  { href: "/proto/app/report", label: "Report" },
  { href: "/proto/app/settings", label: "Settings" },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { repos, openPaths, plan } = useProto();

  return (
    <div className="pr-app">
      <aside className="pr-side">
        <div className="pr-side-top">
          <Link href="/proto" className="pr-mark" style={{ fontSize: 18, marginBottom: 16 }}>
            <Mark size={18} /> ShipLock
          </Link>
          <select className="pr-repo" defaultValue={repos[0]} aria-label="Repository">
            {repos.map((r) => <option key={r}>{r}</option>)}
          </select>
        </div>
        <nav>
          {NAV.map((n) => (
            <Link key={n.href} href={n.href} className={path === n.href ? "on" : ""}>
              <span>{n.label}</span>
              {n.badge && openPaths.length ? <span className="pr-side-count">{openPaths.length}</span> : null}
            </Link>
          ))}
        </nav>
        <div className="pr-side-foot">
          <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span className="pr-dot pr-dot-live" /> Watching · next deep audit in 6h
          </div>
          <div style={{ marginTop: 8, textTransform: "capitalize" }}>{plan} plan · 3 repos</div>
        </div>
      </aside>
      <main className="pr-main">{children}</main>
    </div>
  );
}
