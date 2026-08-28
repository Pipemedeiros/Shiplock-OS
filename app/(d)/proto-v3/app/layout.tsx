"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ChevronDown, FileCheck2, LayoutDashboard, Layers, Route, Settings } from "lucide-react";
import { useStore } from "../store";
import { Mark } from "../ui";

const NAV = [
  { href: "/proto-v3/app", label: "Overview", icon: LayoutDashboard },
  { href: "/proto-v3/app/risks", label: "Risks", icon: Route, count: true },
  { href: "/proto-v3/app/activity", label: "Activity", icon: Activity },
  { href: "/proto-v3/app/coverage", label: "Coverage", icon: Layers },
  { href: "/proto-v3/app/report", label: "Report", icon: FileCheck2 },
  { href: "/proto-v3/app/settings", label: "Settings", icon: Settings },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { openRisks, repos, paused, toast } = useStore();

  return (
    <div className="v3-app">
      <aside className="v3-side">
        <Link href="/proto-v3" className="v3-side-brand"><Mark size={19} /> <span>ShipLock</span></Link>

        <button className="v3-repo" onClick={() => toast("Repository switcher is visual in this prototype")}>
          <div style={{ minWidth: 0 }}>
            <b>{repos[0]}</b>
            <small>{repos.length} repositories · main</small>
          </div>
          <ChevronDown size={14} style={{ marginLeft: "auto", color: "var(--muted-2)" }} />
        </button>

        <nav className="v3-nav">
          {NAV.map((n) => {
            const Icon = n.icon;
            return (
              <Link key={n.href} href={n.href} className={path === n.href ? "on" : ""}>
                <Icon size={16} />
                <span>{n.label}</span>
                {n.count && openRisks.length ? <span className="v3-nav-count">{openRisks.length}</span> : null}
              </Link>
            );
          })}
        </nav>

        <div className="v3-side-foot">
          <span className="v3-row" style={{ gap: 7 }}>
            <i className={`v3-dot ${paused ? "" : "live"}`} />
            {paused ? "Paused — monitoring only" : "Watching · next audit in 6h"}
          </span>
          <span>Startup plan</span>
        </div>
      </aside>

      <main className="v3-main">{children}</main>
    </div>
  );
}
