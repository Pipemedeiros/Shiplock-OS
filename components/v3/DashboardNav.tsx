"use client";

import Link, { useLinkStatus } from "next/link";
import { usePathname } from "next/navigation";
import { Activity, GitPullRequest, Layers, LayoutDashboard, Boxes, Radar, Route, Settings } from "lucide-react";

const ICONS = {
  overview: LayoutDashboard,
  risks: Route,
  activity: Activity,
  traffic: Radar,
  coverage: Layers,
  stack: Boxes,
  prs: GitPullRequest,
  settings: Settings,
} as const;

interface NavItem {
  href: string;
  label: string;
  icon: keyof typeof ICONS;
  count?: number;
}

/** A dot on the clicked tab until its page arrives, so a click always registers. */
function Pending() {
  const { pending } = useLinkStatus();
  return <span aria-hidden className={`v3-nav-pending${pending ? " on" : ""}`} />;
}

/** Client half of the shell — it only needs the pathname to mark the active tab. */
export function DashboardNav({ items }: { items: NavItem[] }) {
  const path = usePathname();

  return (
    <nav className="v3-nav">
      {items.map((item) => {
        const Icon = ICONS[item.icon];
        return (
          <Link key={item.href} href={item.href} className={path === item.href ? "on" : ""}>
            <Icon size={16} />
            <span>{item.label}</span>
            {item.count ? <span className="v3-nav-count">{item.count}</span> : null}
            <Pending />
          </Link>
        );
      })}
    </nav>
  );
}
