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
    <main className="v3">
      <GoogleOneTap next={nextPath} />
      <div className="v3-band">
        <div className="v3-shell">
          <nav className="v3-nav-top">
            <Link href="/" className="v3-mark"><LockMark size={20} /> ShipLock</Link>
          </nav>
        </div>
      </div>
      <div className="v3-auth-wrap">
        <AuthForm oauthError={params.error === "oauth_failed"} nextPath={nextPath} />
      </div>
    </main>
  );
}
