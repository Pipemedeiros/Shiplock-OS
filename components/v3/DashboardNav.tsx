"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, Layers, LayoutDashboard, Route, Settings } from "lucide-react";

const ICONS = {
  overview: LayoutDashboard,
  risks: Route,
  activity: Activity,
  coverage: Layers,
  settings: Settings,
} as const;

export interface NavItem {
  href: string;
  label: string;
  icon: keyof typeof ICONS;
  count?: number;
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
          </Link>
        );
      })}
    </nav>
  );
}
