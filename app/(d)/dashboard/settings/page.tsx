import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getRepositories } from "@/lib/agent/dashboardData";
import { isSupabaseMgmtConfigured } from "@/lib/deep/supabaseMgmt";
import { SupabasePanel } from "@/components/d/SupabasePanel";
import { PostgresPanel } from "@/components/d/PostgresPanel";
import { VerifiedPanel } from "@/components/d/VerifiedPanel";
import { IntelligencePanel } from "@/components/d/IntelligencePanel";
import { TrafficSites } from "@/components/d/TrafficSites";
import { BILLING_ENABLED } from "@/lib/access";

export const metadata = { title: "Settings" };

/**
 * Connections and account. Everything here is setup rather than security state,
 * which is why it is off the Overview page.
 *
 * Billing is absent by design while the MVP is open (lib/access.ts). Showing a
 * disabled plan panel would raise a question the product cannot answer yet.
 */
export default async function SettingsPage() {
  const { userId, email } = await requireDashboardSession();
  const admin = getSupabaseAdmin();

  const [{ data: profile }, repos] = await Promise.all([
    admin
      .from("user_profiles")
      .select(
        "github_installation_id, is_paid, supabase_mgmt_token_encrypted, supabase_mgmt_project_ref, monitored_project_url, monitored_anon_key_encrypted, postgres_dsn_encrypted, postgres_display, verified_report_enabled, verified_report_token, monitored_app_url"
      )
      .eq("id", userId)
      .single(),
    getRepositories(userId),
  ]);

  const githubConnected = Boolean(profile?.github_installation_id);
  const supabaseConnected = Boolean(profile?.supabase_mgmt_token_encrypted);
  const supabaseProjectRef = typeof profile?.supabase_mgmt_project_ref === "string" ? profile.supabase_mgmt_project_ref : null;
  const postgresConnected = Boolean(profile?.postgres_dsn_encrypted);
  const endpointConnected = typeof profile?.monitored_project_url === "string" && profile.monitored_project_url.length > 0 &&
    typeof profile?.monitored_anon_key_encrypted === "string" && profile.monitored_anon_key_encrypted.length > 0;
  const databaseConnected = supabaseConnected || endpointConnected || postgresConnected;
  const showSupabase = !postgresConnected && (isSupabaseMgmtConfigured() || supabaseConnected || endpointConnected);

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <p className="v3-eyebrow">Connections and account</p>
          <h1 className="v3-serif">Settings</h1>
        </div>
      </div>

      <div className="v3-stack">
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">GitHub</h2>
            <span className={`v3-tag ${githubConnected ? "ok" : ""}`}>
              {githubConnected ? "connected" : "not connected"}
            </span>
          </div>
          <div className="v3-card-p">
            <div className="v3-setting">
              <div>
                <b>{githubConnected ? "The app is installed" : "Connect GitHub"}</b>
                <small>
                  {repos.length > 0
                    ? repos.map((r) => r.fullName).join(" · ")
                    : "No repositories selected yet."}
                </small>
              </div>
              {githubConnected ? (
                <Link href="/onboarding" className="v3-btn v3-btn-sm v3-ghost">Change repositories</Link>
              ) : (
                <a href="/api/deep/github/connect" className="v3-btn v3-btn-sm v3-primary">Install</a>
              )}
            </div>
          </div>
        </div>

        {/* The customer's own AI funds deep scans and PR reasoning after the
            first scan. The card owns its state through /api/intelligence/connection. */}
        <div className="v3-card">
          <div className="v3-hd"><h2 className="v3-eyebrow">Your AI</h2></div>
          <div className="v3-card-p"><IntelligencePanel /></div>
        </div>

        {/* Traffic bound to a repository through a site (2F-2b). Enabled mirrors
            the ingest rule (is_paid; free vs paid is parked by Felipe). */}
        <div className="v3-card">
          <div className="v3-hd"><h2 className="v3-eyebrow">Traffic, optional</h2></div>
          <div className="v3-card-p">
            <TrafficSites enabled={profile?.is_paid === true} repositories={repos.map((r) => ({ id: r.id, fullName: r.fullName }))} />
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Database, optional</h2>
            <span className={`v3-tag ${databaseConnected ? "ok" : ""}`}>
              {databaseConnected ? "connected" : "not connected"}
            </span>
          </div>
          <div className="v3-card-p">
            <p className="v3-sub" style={{ fontSize: 14, marginBottom: 16, maxWidth: 700 }}>
              A read-only connection lets us reproduce a finding on a disposable copy of your schema
              instead of reading it from code alone, which is the difference between an inferred
              finding and a proven one. It is not required, and nothing is withheld without it.
            </p>
            {showSupabase ? (
              <SupabasePanel connected={supabaseConnected} projectRef={supabaseProjectRef} configured={isSupabaseMgmtConfigured()} />
            ) : (
              <PostgresPanel connected={postgresConnected} display={profile?.postgres_display ?? null} />
            )}
          </div>
        </div>

        {/* The shareable assessment. Lives beside the connections because that
            is where a customer goes once an audit has run and someone has asked
            them a security question. */}
        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Shareable assessment</h2>
            <span className={`v3-tag ${profile?.verified_report_enabled ? "ok" : ""}`}>
              {profile?.verified_report_enabled ? "published" : "not published"}
            </span>
          </div>
          <div className="v3-card-p">
            <VerifiedPanel
              initialEnabled={Boolean(profile?.verified_report_enabled)}
              initialToken={(profile?.verified_report_token as string | null) ?? null}
              appUrl={(profile?.monitored_app_url as string | null) ?? ""}
            />
          </div>
        </div>

        <div className="v3-card">
          <div className="v3-hd"><h2 className="v3-eyebrow">Account</h2></div>
          <div className="v3-card-p">
            <div className="v3-setting">
              <div>
                <b>{email}</b>
                <small>
                  {BILLING_ENABLED
                    ? "Billing is active."
                    : "ShipLock is free while it is in preview. There is nothing to pay and no card on file."}
                </small>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
