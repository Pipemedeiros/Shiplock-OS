"use client";

// Dashboard section navigation. The dashboard used to be one long page that
// did everything; it's now four surfaces, and this is how you move between
// them. Active state comes from the pathname so a hard refresh or a deep link
// lands with the right tab lit.

import Link from "next/link";
import { usePathname } from "next/navigation";

const TABS = [
  { href: "/dashboard", label: "Overview" },
  { href: "/dashboard/findings", label: "Findings" },
  { href: "/dashboard/watch", label: "Watch" },
  { href: "/dashboard/settings", label: "Settings" },
] as const;

export function DashboardTabs({ findingCount = 0 }: { findingCount?: number }) {
  const pathname = usePathname();

  return (
    <nav className="dxd-tabs" aria-label="Dashboard sections">
      {TABS.map((tab) => {
        // "/dashboard" would otherwise match every child route.
        const active =
          tab.href === "/dashboard" ? pathname === "/dashboard" : pathname.startsWith(tab.href);
        return (
          <Link
            key={tab.href}
            href={tab.href}
            className="dxd-tab"
            data-active={active}
            aria-current={active ? "page" : undefined}
          >
            {tab.label}
            {tab.label === "Findings" && findingCount > 0 && (
              <span className="dxd-tab-count">{findingCount}</span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}
