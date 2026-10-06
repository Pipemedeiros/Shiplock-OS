import type { Metadata } from "next";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { safeNext } from "@/lib/authRedirect";
import { MfaChallenge } from "@/components/v3/TwoStep";

export const metadata: Metadata = { title: "Enter your code" };

/**
 * The code step of two-step sign-in. Every dashboard page sends a session that
 * still needs its code here (lib/mfa.ts); this page never calls the dashboard
 * gate, so it cannot loop.
 */
export default async function MfaPage({ searchParams }: { searchParams: Promise<{ next?: string | string[] }> }) {
  const params = await searchParams;
  const next = safeNext(typeof params.next === "string" ? params.next : undefined, "/dashboard");
  const { data, error } = await (await getSupabaseServer()).auth.getClaims();
  const claims = error ? null : data?.claims;
  if (!claims?.sub) redirect("/auth");
  if (claims.aal === "aal2") redirect(next);

  return (
    <main className="v3" style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "64px 16px" }}>
      <MfaChallenge next={next} />
    </main>
  );
}
