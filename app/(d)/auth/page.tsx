import Link from "next/link";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { AuthForm } from "@/components/auth-form";
import { LockMark } from "@/components/d/Brand";

export default async function AuthPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  const supabase = await getSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (user) {
    redirect("/dashboard");
  }

  const { error } = await searchParams;

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
      <AuthForm oauthError={error === "oauth_failed"} />
    </main>
  );
}
