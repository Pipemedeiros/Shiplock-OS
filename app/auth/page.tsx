import Link from "next/link";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { Logo } from "@/components/logo";
import { AuthForm } from "@/components/auth-form";

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
      className="flex min-h-screen flex-col items-center justify-center px-6 py-16"
      style={{ backgroundColor: "#0a0a0f" }}
    >
      <Link href="/" className="mb-10">
        <Logo />
      </Link>
      <AuthForm oauthError={error === "oauth_failed"} />
    </main>
  );
}
