import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { AuthForm } from "@/components/auth-form";
import { GoogleOneTap } from "@/components/GoogleOneTap";
import { LockMark } from "@/components/d/Brand";
import { safeNext } from "@/lib/authRedirect";

export const metadata: Metadata = {
  title: "Sign in",
  description:
    "Sign in to ShipLock with email, Google, or GitHub.",
};


export default async function AuthPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string | string[]; next?: string | string[] }>;
}) {
  const params = await searchParams;
  const requestedNext = typeof params.next === "string" ? params.next : undefined;
  const nextPath = safeNext(requestedNext, "/dashboard");
  const supabase = await getSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) {
    redirect(nextPath);
  }

  return (
    <main
      className="dxd"
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "64px 24px",
      }}
    >
      <GoogleOneTap next={nextPath} />
      <Link
        href="/"
        className="dxd-wordmark"
        style={{ marginBottom: 40, display: "inline-flex", alignItems: "center", gap: 8 }}
      >
        <span className="dxd-wordmark-lock">
          <LockMark size={19} />
        </span>
        ShipLock
      </Link>
      <AuthForm oauthError={params.error === "oauth_failed"} nextPath={nextPath} />
    </main>
  );
}
