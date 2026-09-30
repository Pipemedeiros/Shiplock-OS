import Link from "next/link";
import { requireDashboardSession } from "@/lib/dashboard";
import { StatusPage } from "@/components/v3/StatusPage";

export const metadata = { title: "You are set up" };

const NEXT = [
  { href: "/dashboard", title: "See your route map", body: "Every route the audit read, the tables it reaches, and what is open." },
  { href: "/dashboard/risks", title: "Review what the audit found", body: "Each finding says what could happen, the code behind it, and the next safe step." },
  { href: "/dashboard/settings", title: "Connect more of your stack", body: "Your database, read only, and the traffic snippet add what code alone cannot show." },
];

export default async function Welcome() {
  await requireDashboardSession();
  return (
    <StatusPage eyebrow="Setup complete" title="Thank you. ShipLock is watching your repository.">
      <p className="v3-sub" style={{ fontSize: 16.5, maxWidth: 580 }}>
        Pull requests on the repositories you selected now get a ShipLock check, and changes are rechecked.
        Nothing is merged or deployed without your click.
      </p>
      <div className="v3-row" style={{ gap: 12, marginTop: 28 }}>
        <Link href="/dashboard" className="v3-btn v3-primary">Open your dashboard</Link>
      </div>
      <section aria-labelledby="next" style={{ marginTop: 48 }}>
        <h2 id="next" className="v3-small v3-mono" style={{ textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 12 }}>
          What to do next
        </h2>
        <ul style={{ listStyle: "none", padding: 0, display: "grid", gap: 10 }}>
          {NEXT.map((item) => (
            <li key={item.href}>
              <Link href={item.href} className="v3-card" style={{ display: "block", padding: "14px 18px" }}>
                <span style={{ fontWeight: 500 }}>{item.title}</span>
                <span className="v3-small" style={{ display: "block", marginTop: 2 }}>{item.body}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </StatusPage>
  );
}
