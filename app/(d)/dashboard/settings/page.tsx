import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getRepositories } from "@/lib/agent/dashboardData";
import { isSupabaseMgmtConfigured } from "@/lib/deep/supabaseMgmt";
import { SupabasePanel } from "@/components/d/SupabasePanel";
import { PostgresPanel } from "@/components/d/PostgresPanel";
import { BILLING_ENABLED } from "@/lib/access";

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
      .select("github_installation_id, supabase_mgmt_token_encrypted, postgres_dsn_encrypted, postgres_display")
      .eq("id", userId)
      .single(),
    getRepositories(userId),
  ]);

  const githubConnected = Boolean(profile?.github_installation_id);
  const supabaseConnected = Boolean(profile?.supabase_mgmt_token_encrypted);
  const postgresConnected = Boolean(profile?.postgres_dsn_encrypted);
  const databaseConnected = supabaseConnected || postgresConnected;

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

        <div className="v3-card">
          <div className="v3-hd">
            <h2 className="v3-eyebrow">Database — optional</h2>
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
            {isSupabaseMgmtConfigured() && !postgresConnected ? (
              <SupabasePanel connected={supabaseConnected} projectRef={null} configured={isSupabaseMgmtConfigured()} />
            ) : (
              <PostgresPanel connected={postgresConnected} display={profile?.postgres_display ?? null} />
            )}
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
