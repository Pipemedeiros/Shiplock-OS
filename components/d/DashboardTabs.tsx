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

export function DashboardTabs({
  findingCount = 0,
  demo = false,
}: {
  findingCount?: number;
  /**
   * Public preview: render the real tab bar, but inert. Linking would send a
   * logged-out visitor into the auth wall, which is the opposite of what a
   * preview is for.
   */
  demo?: boolean;
}) {
  const pathname = usePathname();

  return (
    <nav className="dxd-tabs" aria-label="Dashboard sections">
      {TABS.map((tab) => {
        // "/dashboard" would otherwise match every child route.
        const active = demo
          ? tab.href === "/dashboard"
          : tab.href === "/dashboard"
            ? pathname === "/dashboard"
            : pathname.startsWith(tab.href);

        if (demo) {
          return (
            <span key={tab.href} className="dxd-tab" data-active={active} aria-disabled="true">
              {tab.label}
              {tab.label === "Findings" && findingCount > 0 && (
                <span className="dxd-tab-count">{findingCount}</span>
              )}
            </span>
          );
        }

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
