"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Bell,
  Boxes,
  ChevronDown,
  CircleDotDashed,
  FileCheck2,
  GitPullRequestArrow,
  LayoutDashboard,
  Menu,
  PanelLeftClose,
  Route,
  Search,
  Settings,
  X,
} from "lucide-react";
import { useState } from "react";
import { RISKS } from "../data";
import { useConcept } from "../store";
import { Brand } from "../ui";

const NAV = [
  { href: "/proto-codex/app", label: "Overview", icon: LayoutDashboard },
  { href: "/proto-codex/app/paths", label: "Attack paths", icon: Route, count: true },
  { href: "/proto-codex/app/prs", label: "Pull requests", icon: GitPullRequestArrow },
  { href: "/proto-codex/app/runs", label: "Audit runs", icon: Activity },
  { href: "/proto-codex/app/stack", label: "Your stack", icon: Boxes },
  { href: "/proto-codex/app/report", label: "Report", icon: FileCheck2 },
  { href: "/proto-codex/app/settings", label: "Settings", icon: Settings },
];

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { activeRepo, dismissed, compactMode, update, toast } = useConcept();
  const [mobileOpen, setMobileOpen] = useState(false);
  const openCount = RISKS.filter((risk) => !dismissed.includes(risk.id)).length;

  return (
    <div className={`cx-app${compactMode ? " is-compact" : ""}`}>
      <aside className={`cx-sidebar${mobileOpen ? " is-open" : ""}`}>
        <div className="cx-side-brand">
          <Link href="/proto-codex" aria-label="Back to concept landing"><Brand /></Link>
          <button className="cx-side-collapse" onClick={() => update({ compactMode: !compactMode })} aria-label="Toggle compact navigation">
            <PanelLeftClose size={16} />
          </button>
          <button className="cx-side-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X size={18} /></button>
        </div>

        <button className="cx-repo-switch" onClick={() => toast("Repository switcher is visual in this concept") }>
          <span className="cx-repo-icon">LL</span>
          <span className="cx-repo-copy"><strong>{activeRepo}</strong><small>Production · main</small></span>
          <ChevronDown size={14} />
        </button>

        <nav className="cx-side-nav" aria-label="Concept dashboard">
          <p className="cx-side-label">Workspace</p>
          {NAV.slice(0, 5).map((item) => {
            const active = pathname === item.href;
            const Icon = item.icon;
            return (
              <Link key={item.href} href={item.href} className={active ? "is-active" : ""} onClick={() => setMobileOpen(false)}>
                <span className="cx-nav-icon"><Icon size={16} /></span>
                <span className="cx-nav-label">{item.label}</span>
                {item.count ? <span className="cx-nav-count">{openCount}</span> : null}
              </Link>
            );
          })}
          <p className="cx-side-label is-second">Share &amp; control</p>
          {NAV.slice(5).map((item) => {
            const active = pathname === item.href;
            const Icon = item.icon;
            return (
              <Link key={item.href} href={item.href} className={active ? "is-active" : ""} onClick={() => setMobileOpen(false)}>
                <span className="cx-nav-icon"><Icon size={16} /></span>
                <span className="cx-nav-label">{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="cx-watch-card">
          <div className="cx-watch-orbit"><CircleDotDashed size={23} /></div>
          <div><strong>Watch is live</strong><small>Next deep audit in 6h 18m</small></div>
        </div>

        <div className="cx-user-card">
          <span className="cx-avatar">FM</span>
          <span><strong>Felipe</strong><small>Startup plan</small></span>
          <button aria-label="Open account menu"><ChevronDown size={13} /></button>
        </div>
      </aside>

      {mobileOpen ? <button className="cx-mobile-scrim" onClick={() => setMobileOpen(false)} aria-label="Close navigation overlay" /> : null}

      <div className="cx-workspace">
        <div className="cx-topbar">
          <button className="cx-mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={18} /></button>
          <div className="cx-breadcrumb"><span>ledgerloop</span><i>/</i><strong>app</strong><em>main</em></div>
          <div className="cx-top-actions">
            <button className="cx-command" onClick={() => toast("Command palette opened — visual demo") }><Search size={14} /><span>Search evidence</span><kbd>⌘ K</kbd></button>
            <button className="cx-icon-button has-alert" onClick={() => toast("1 new audit event") } aria-label="Notifications"><Bell size={16} /></button>
            <button className="cx-run-button" onClick={() => toast("Deep audit queued — display only") }><Activity size={14} />Run audit</button>
          </div>
        </div>
        <main className="cx-main">{children}</main>
        <footer className="cx-app-footer">
          <span><i className="cx-status-dot is-verified" />All monitoring systems observing</span>
          <span>Prototype · sample data · no services connected</span>
        </footer>
      </div>
    </div>
  );
}
