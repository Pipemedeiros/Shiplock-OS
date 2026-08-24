import { requireDashboardSession } from "@/lib/dashboard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { isBetterAuthConfigured } from "@/lib/betterAuth";
import { env } from "@/lib/env";
import { VerifiedPanel } from "@/components/d/VerifiedPanel";
import { McpPanel } from "@/components/d/McpPanel";
import { TwoFactorSetup } from "@/components/d/TwoFactorSetup";
import { GitHubPanel } from "@/components/d/GitHubPanel";
import { SupabasePanel } from "@/components/d/SupabasePanel";
import { PostgresPanel } from "@/components/d/PostgresPanel";
import { isSupabaseMgmtConfigured } from "@/lib/deep/supabaseMgmt";
import { ManageBillingButton } from "@/components/d/ManageBillingButton";
import { UpgradeButton } from "@/components/d/UpgradeButton";
import { Reveal } from "@/components/d/bits";

// Settings — connections, sharing, tokens, billing. Everything here is setup
// rather than security state, which is why it's off the Overview page.
export default async function DashboardSettingsPage() {
  const { userId, isPaid } = await requireDashboardSession();

  if (!isPaid) {
    return (
      <section style={{ paddingTop: 40 }}>
        <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
          Terms of engagement
        </p>
        <div className="dxd-connect-card">
          <div>
            <h4>Your retainer isn&apos;t active</h4>
            <p>
              Connections, the Verified report, and coding-agent access all resume with the
              subscription.
            </p>
          </div>
          <span className="dxd-connect-cta">
            <UpgradeButton />
          </span>
        </div>
      </section>
    );
  }

  const admin = getSupabaseAdmin();
  const githubConfigured = Boolean(env.GITHUB_APP_SLUG);

  const [{ data: profile }, { data: mcpTokens }] = await Promise.all([
    admin
      .from("user_profiles")
      .select(
        "verified_report_enabled, verified_report_token, github_installation_id, supabase_mgmt_connected_at, supabase_mgmt_project_ref, postgres_connected_at, postgres_display"
      )
      .eq("id", userId)
      .maybeSingle(),
    admin
      .from("api_tokens")
      .select("id, name, created_at, last_used_at")
      .eq("user_id", userId)
      .is("revoked_at", null)
      .order("created_at", { ascending: false }),
  ]);

  const supabaseConnected = Boolean(profile?.supabase_mgmt_connected_at);
  const postgresConnected = Boolean(profile?.postgres_connected_at);

  return (
    <>
      <section style={{ paddingTop: 32 }}>
        <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
          Connections
        </p>
        {githubConfigured && (
          <GitHubPanel connected={Boolean(profile?.github_installation_id)} findings={[]} />
        )}
        {/*
          One "your database" slot, two ways to fill it. Supabase OAuth is the
          smaller ask, so it stays the default; the direct-Postgres panel appears
          for everyone else. Showing both at once would read as two required
          connections and break the two-connection friction budget in the only
          way that matters — how it looks to the customer.
        */}
        <div style={{ marginTop: githubConfigured ? 20 : 0 }}>
          {postgresConnected || !supabaseConnected ? (
            <PostgresPanel
              connected={postgresConnected}
              display={(profile?.postgres_display as string | null) ?? null}
            />
          ) : null}
          {!postgresConnected && (
            <div style={{ marginTop: supabaseConnected ? 0 : 20 }}>
              <SupabasePanel
                connected={supabaseConnected}
                projectRef={(profile?.supabase_mgmt_project_ref as string | null) ?? null}
                configured={isSupabaseMgmtConfigured()}
              />
            </div>
          )}
        </div>
      </section>

      <Reveal>
        <VerifiedPanel
          initialEnabled={Boolean(profile?.verified_report_enabled)}
          initialToken={(profile?.verified_report_token as string | null) ?? null}
          appUrl={env.NEXT_PUBLIC_APP_URL}
        />
      </Reveal>

      <Reveal>
        <McpPanel initialTokens={mcpTokens ?? []} />
      </Reveal>

      {/* 2FA appears only once Better Auth is configured (env vars set) —
          enrollment is opt-in, so a gated mount can never lock anyone out. */}
      {isBetterAuthConfigured() && (
        <Reveal>
          <TwoFactorSetup />
        </Reveal>
      )}

      <section style={{ marginTop: 40 }} aria-label="Billing">
        <p className="dxd-panel-label" style={{ margin: "0 0 12px" }}>
          Billing
        </p>
        <div className="dxd-surface">
          <p style={{ margin: "0 0 14px", fontSize: 13.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
            Update your card, download invoices, or cancel — all self-serve through Stripe.
            Cancelling stops the watch at the end of the period you&apos;ve paid for; nothing is
            deleted.
          </p>
          <ManageBillingButton />
        </div>
      </section>
    </>
  );
}
