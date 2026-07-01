import Link from "next/link";
import { redirect } from "next/navigation";
import { getSupabaseServer } from "@/lib/supabaseServer";
import { Logo } from "@/components/logo";
import { SignOutButton } from "@/components/sign-out-button";

export default async function DashboardPage() {
  const supabase = await getSupabaseServer();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user) {
    redirect("/auth");
  }

  // RLS-scoped read — the "users can read own profile" policy restricts
  // this to the caller's own row regardless of which auth method they used.
  const { data: profile } = await supabase
    .from("user_profiles")
    .select("is_paid")
    .eq("id", user.id)
    .single();

  const provider = user.app_metadata?.provider ?? "email";

  return (
    <main className="min-h-screen" style={{ backgroundColor: "#0a0a0f" }}>
      <header className="mx-auto flex max-w-6xl items-center justify-between border-b border-white/[0.06] px-6 py-5">
        <Link href="/">
          <Logo />
        </Link>
        <SignOutButton />
      </header>

      <div className="mx-auto max-w-2xl px-6 py-16">
        <h1 className="text-2xl font-semibold text-white">Dashboard</h1>
        <div className="mt-6 rounded-[10px] border border-[#1f2937] bg-[#080808] p-6">
          <dl className="space-y-3 text-sm">
            <div className="flex justify-between">
              <dt className="text-[#71717a]">Email</dt>
              <dd className="text-white">{user.email}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[#71717a]">Signed in via</dt>
              <dd className="text-white capitalize">{provider}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-[#71717a]">Plan</dt>
              <dd className="text-white">{profile?.is_paid ? "Pro" : "Free"}</dd>
            </div>
          </dl>
        </div>
      </div>
    </main>
  );
}
