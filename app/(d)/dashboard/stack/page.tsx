import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { getRuns } from "@/lib/agent/dashboardData";
import { StackConnection, StackDepth, connectionFor, depthOf } from "@/components/v3/StackDepth";
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
  const runs = await getRuns(userId, 1);
  const latest = runs[0];
  const stack = latest?.stack ?? null;
  const domain = latest?.domain ?? null;

  return (
    <>
      <div className="v3-page-hd">
        <div>
          <h1>Stack</h1>
          <p className="v3-sub" style={{ marginTop: 8, maxWidth: 620 }}>
            Your repository already declares what your system talks to: the manifest, the imports,
            the environment variable names, the schema. Nothing here was typed in.
          </p>
        </div>
      </div>

      {!latest ? (
        <div className="v3-empty">
          <p>No audit has run yet, so there is nothing read.</p>
          <Link href="/onboarding" className="v3-btn v3-btn-sm v3-primary" style={{ marginTop: 16 }}>
            Run the first audit
          </Link>
        </div>
      ) : !stack ? (
        // Deliberately not an empty stack: this run predates the column, and
        // "we did not record it" must not render as "your app uses nothing".
        <div className="v3-empty">
          <p>This audit ran before we started recording the stack. The next one will show it.</p>
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
                {domain.tenantKey ? (
                  <p className="v3-sub" style={{ marginTop: 12, fontSize: 14 }}>
                    We treat <code className="v3-file">{domain.tenantKey}</code> as the line between
                    one customer and another. A route that reads a table without it is reading across
                    that line, and that is the first thing every audit looks for.
                  </p>
                ) : (
                  <p className="v3-sub" style={{ marginTop: 12, fontSize: 14 }}>
                    We could not identify the column that separates one customer&apos;s rows from
                    another&apos;s, so we do not assume one. Findings about cross-customer access stay
                    conservative rather than guessing at your ownership model.
                  </p>
                )}
                <p className="v3-small" style={{ marginTop: 12 }}>
                  Read from your schema and routes. It shapes what the audit looks for, and is never
                  a finding on its own.
                </p>
              </div>
            </div>
          ) : null}

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">{stack.tools.length} identified</h2>
              <span className="v3-small">
                from {latest.fullName} · <When at={latest.startedAt} date />
              </span>
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
                    <StackConnection connection={connectionFor(tool)} />
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
                    <strong style={{ fontWeight: 500 }}>No auth provider recognised.</strong>{" "}
                    Findings that turn on who a caller is stay inferred. We cannot tell an
                    unauthenticated route from one guarded by something we do not know the shape of.
                  </p>
                ) : null}
                {stack.databaseUnknown ? (
                  <p>
                    <strong style={{ fontWeight: 500 }}>No database recognised.</strong>{" "}
                    We can see which code paths exist, not what they read. Table-level reasoning is
                    limited to what the schema files declare.
                  </p>
                ) : null}
              </div>
            </div>
          )}

          <div className="v3-card">
            <div className="v3-hd">
              <h2 className="v3-eyebrow">Needs a live connection</h2>
            </div>
            <div className="v3-card-p">
              <p style={{ maxWidth: 720 }}>
                A row policy, a bucket permission and a production environment variable do not live
                in your repository. Findings that depend on them are labelled{" "}
                <strong style={{ fontWeight: 500 }}>inferred</strong> and stay that way. Connecting
                your database read-only turns some of them into findings we can reproduce. That is an
                upgrade, never a requirement.
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
        </div>
      )}
    </>
  );
}
