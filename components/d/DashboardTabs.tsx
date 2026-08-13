"use client";

// Dashboard section navigation. The dashboard used to be one long page that
// did everything; it's now four surfaces, and this is how you move between
// them. Active state comes from the pathname so a hard refresh or a deep link
// lands with the right tab lit.

import Link from "next/link";
import { usePathname } from "next/navigation";

// "Risks" rather than "Findings": a finding is what a scanner emits, and the
// product's claim is that layers agree about a risk. "Activity" rather than
// "Watch": the log of what we checked is the smaller half of what belongs
// there — as autonomous Tier 1-3 actions land, the question a customer needs
// this tab to answer becomes "what did ShipLock do to my production app, when,
// and how do I undo it", and two competing "what happened" surfaces is the one
// thing this product cannot afford.
const TABS = [
  { href: "/dashboard", label: "Overview" },
  { href: "/dashboard/risks", label: "Risks" },
  { href: "/dashboard/activity", label: "Activity" },
  { href: "/dashboard/settings", label: "Settings" },
] as const;

/** The tab that carries the open-finding count. */
const COUNT_TAB = "Risks";

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
              {tab.label === COUNT_TAB && findingCount > 0 && (
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
            {tab.label === COUNT_TAB && findingCount > 0 && (
              <span className="dxd-tab-count">{findingCount}</span>
            )}
          </Link>
        );
      })}
    </nav>
  );
}
