import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getRuns } from "@/lib/agent/dashboardData";
import { StackConnection, StackDepth, connectionFor, depthOf, type LiveProvider } from "@/components/v3/StackDepth";
import { When } from "@/components/v3/When";

/**
 * What we read out of the repository, and how deeply we reasoned about each of
 * it.
 *
 * This page is the argument for starting with GitHub, made concrete. The
 * customer typed one thing, an installation, and this is everything the product
 * worked out from it. Every row names its evidence, because a claim about
 * someone's own architecture that they cannot check is a claim they have to
 * take on faith, and this product does not ask for faith.
 *
 * Each service they go on to connect adds the live configuration this page can
 * only infer. That is the offer, and it is always optional.
 *
 * The depth column is the honest half. "Detected" and "reasoned about" are
 * different claims, and a page that showed a flat list of logos would let the
 * first quietly borrow the credibility of the second.
 */
export const metadata = { title: "Stack" };

export default async function Stack() {
  const { userId } = await requireDashboardSession();
  const [runs, { data: profile }] = await Promise.all([
    getRuns(userId, 1),
    getSupabaseAdmin().from("user_profiles")
      .select("supabase_mgmt_token_encrypted, monitored_project_url, monitored_anon_key_encrypted, postgres_dsn_encrypted")
      .eq("id", userId).maybeSingle(),
  ]);
  // The same tests Settings uses: a founder who connected must not be asked to connect.
  const connected = new Set<LiveProvider>();
  if (profile?.supabase_mgmt_token_encrypted || (profile?.monitored_project_url && profile?.monitored_anon_key_encrypted)) connected.add("Supabase");
  if (profile?.postgres_dsn_encrypted) connected.add("Postgres");
  const latest = runs[0];
  const stack = latest?.stack ?? null;
  const domain = latest?.domain ?? null;

  return (
    <>
      <div className="v3-page-hd">
        <div>
          {latest ? <p className="v3-eyebrow">{latest.fullName} · Last audit <When at={latest.startedAt} /></p> : null}
          <h1>Stack</h1>
        </div>
      </div>

      {!latest ? (
        <div className="v3-empty">
          <p>No audits yet.</p>
          <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 16 }}>
            Run an audit
          </Link>
        </div>
      ) : !stack ? (
        // Deliberately not an empty stack: this run predates the column, and
        // "we did not record it" must not render as "your app uses nothing".
        <div className="v3-empty">
          <p>Your stack appears after the next audit.</p>
        </div>
      ) : (
        <div className="v3-stack">
          {domain ? (
            <div className="v3-card">
              <div className="v3-hd">
                <h2 className="v3-eyebrow">Product</h2>
              </div>
              <div className="v3-card-p">
                <p className="v3-serif" style={{ fontSize: 18, lineHeight: 1.45, maxWidth: 720 }}>
                  {domain.summary}
                </p>
                <p className="v3-small" style={{ marginTop: 10 }}>
                  Tenant column:{" "}
                  {domain.tenantKey ? <code className="v3-file">{domain.tenantKey}</code> : "not identified, so cross customer findings stay conservative"}
                </p>
              </div>
            </div>
          ) : null}

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Services</h2>
              <span className="v3-small">{stack.tools.length} detected</span>
            </div>
            <div className="v3-card-p v3-grid-2" style={{ gap: 14 }}>
              {stack.tools.map((tool) => {
                const depth = depthOf(tool.kind);
                return (
                  <div key={tool.id} className="v3-tile">
                    <div className="v3-between" style={{ alignItems: "flex-start" }}>
                      <div>
                        <strong style={{ fontWeight: 500, fontSize: 14.5 }}>{tool.name}</strong>
                        <p className="v3-small" style={{ marginTop: 2, textTransform: "capitalize" }}>
                          {tool.kind.replace(/_/g, " ")}
                        </p>
                      </div>
                      <StackDepth depth={depth} />
                    </div>
                    <p className="v3-file" style={{ marginTop: 10 }}>{tool.evidence}</p>
                    {tool.usedIn.length > 0 ? (
                      <p className="v3-small" style={{ marginTop: 6 }}>
                        Imported in {tool.usedIn.length} file{tool.usedIn.length === 1 ? "" : "s"}
                        {tool.usedIn[0] ? `, ${tool.usedIn[0]}` : ""}
                        {tool.usedIn.length > 1 ? ` +${tool.usedIn.length - 1} more` : ""}
                      </p>
                    ) : null}
                    <StackConnection connection={connectionFor(tool, connected)} />
                  </div>
                );
              })}
            </div>
          </div>

          {(stack.authUnknown || stack.databaseUnknown) && (
            <div className="v3-card v3-card-warn">
              <div className="v3-hd">
                <h2 className="v3-eyebrow">Not identified</h2>
              </div>
              <div className="v3-card-p">
                {stack.authUnknown ? (
                  <p style={{ marginBottom: 8 }}>
                    <strong style={{ fontWeight: 500 }}>Auth provider not identified.</strong>{" "}
                    Findings about who a caller is stay inferred.
                  </p>
                ) : null}
                {stack.databaseUnknown ? (
                  <p>
                    <strong style={{ fontWeight: 500 }}>Database not identified.</strong>{" "}
                    Table checks use schema files only.
                  </p>
                ) : null}
              </div>
            </div>
          )}

          {connected.size > 0 ? null : (
            <div className="v3-card">
              <div className="v3-hd">
                <h2 className="v3-eyebrow">Needs a live connection</h2>
              </div>
              <div className="v3-card-p">
                <p className="v3-sub" style={{ maxWidth: 720, fontSize: 14 }}>
                  Row policies, bucket permissions and production settings live outside your repository.
                  Connect your database read only to verify them. Optional.
                </p>
                <Link
                  href="/dashboard/settings"
                  className="v3-btn v3-btn-sm v3-ghost"
                  style={{ marginTop: 14 }}
                >
                  Connect a database
                </Link>
              </div>
            </div>
          )}
        </div>
      )}
    </>
  );
}
