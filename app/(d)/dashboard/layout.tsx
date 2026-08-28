import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { requireDashboardSession } from "@/lib/dashboard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getOpenFindings, getRepositories } from "@/lib/agent/dashboardData";
import { LockMark } from "@/components/d/Brand";
import { SignOutButton } from "@/components/sign-out-button";
import { DashboardNav } from "@/components/v3/DashboardNav";

export const metadata: Metadata = {
  robots: { index: false, follow: false },
};

/**
 * The shell every dashboard page sits in.
 *
 * Six sections, named the way the product talks about them rather than the way
 * the code is organised. Coverage is a first-class page, not a footnote: a
 * clean report is only worth what it covered, and a customer who cannot see the
 * boundary of an audit cannot judge it.
 */
export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { userId, email } = await requireDashboardSession();

  // A brand new account has nothing to show. Sending them to the dashboard's
  // empty state and asking them to find the link is a dead end; onboarding is
  // where the product actually starts.
  const { data: profile } = await getSupabaseAdmin()
    .from("user_profiles")
    .select("github_installation_id")
    .eq("id", userId)
    .single();
  if (!profile?.github_installation_id) redirect("/onboarding");

  const [findings, repos] = await Promise.all([getOpenFindings(userId), getRepositories(userId)]);

  return (
    <div className="v3">
      <div className="v3-app">
        <aside className="v3-side">
          <Link href="/" className="v3-side-brand"><LockMark size={19} /> <span>ShipLock</span></Link>

          <div className="v3-repo">
            <div style={{ minWidth: 0 }}>
              <b>{repos[0]?.fullName ?? "No repository"}</b>
              <small>
                {repos.length === 0
                  ? "none selected"
                  : `${repos.length} ${repos.length === 1 ? "repository" : "repositories"}`}
              </small>
            </div>
          </div>

          <DashboardNav
            items={[
              { href: "/dashboard", label: "Overview", icon: "overview" },
              { href: "/dashboard/risks", label: "Risks", icon: "risks", count: findings.length },
              {
                href: "/dashboard/prs",
                label: "Pull requests",
                icon: "prs",
                count: findings.filter((f) => f.fixPrUrl).length,
              },
              { href: "/dashboard/stack", label: "Stack", icon: "stack" },
              { href: "/dashboard/activity", label: "Activity", icon: "activity" },
              { href: "/dashboard/coverage", label: "Coverage", icon: "coverage" },
              { href: "/dashboard/settings", label: "Settings", icon: "settings" },
            ]}
          />

          <div className="v3-side-foot">
            <span className="v3-row" style={{ gap: 7 }}>
              <i className="v3-dot live" /> Watching
            </span>
            <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{email}</span>
            <SignOutButton />
          </div>
        </aside>

        <main className="v3-main">{children}</main>
      </div>
    </div>
  );
}
