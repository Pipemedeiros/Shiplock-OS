import { sendEmail } from "@/lib/email";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * Felipe 2026-09-29: a welcome email on sign-up, with the logo. Sent at
 * most once: the auth user is marked (app_metadata.welcome_sent_at, no
 * migration) before the send, so a retry or a second sign-in cannot repeat
 * it; a failed send is logged by sendEmail and not retried. Only accounts
 * created in the last day qualify, so existing users are never emailed.
 */
type AuthUser = { id: string; email?: string | null; created_at?: string; app_metadata?: Record<string, unknown> };

const NEW_ACCOUNT_MS = 24 * 60 * 60 * 1000;

/** The welcome email: the three first steps, as text and HTML. */
export function welcomeMessage(appUrl: string): { subject: string; text: string; html: string } {
  const steps = [
    "Install the GitHub App and pick a repository. ShipLock reads it and names your stack.",
    "Run the first audit. You see the routes we can read that reach data, and what we could not read.",
    "Connect your own AI and, when you want, your database read only and the traffic snippet.",
  ];
  const text = [
    "Welcome to ShipLock.",
    "",
    "Three steps get you to your first result:",
    ...steps.map((s, i) => `${i + 1}. ${s}`),
    "",
    `Continue: ${appUrl}/onboarding`,
    "",
    "ShipLock never merges or deploys. Every pull request waits for your click.",
    "Questions: support@shiplock.dev.",
  ].join("\n");
  const html = `<!doctype html><html><body style="margin:0;background:#f7f8fa;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#122036">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border:1px solid #e3e7ed;border-radius:6px">
<tr><td style="background:#0f1b2d;padding:20px 28px;border-radius:6px 6px 0 0">
<img src="${appUrl}/apple-icon.png" width="28" height="28" alt="" style="vertical-align:middle;border-radius:5px">
<span style="color:#eef2f7;font-size:18px;vertical-align:middle;margin-left:10px">ShipLock</span></td></tr>
<tr><td style="padding:28px">
<h1 style="font-size:22px;font-weight:600;margin:0 0 12px">Welcome to ShipLock.</h1>
<p style="font-size:15px;line-height:1.6;color:#55647a;margin:0 0 16px">Three steps get you to your first result:</p>
<ol style="font-size:15px;line-height:1.6;padding-left:20px;margin:0 0 22px">${steps.map((s) => `<li style="margin-bottom:6px">${s}</li>`).join("")}</ol>
<a href="${appUrl}/onboarding" style="display:inline-block;background:#8a6b2f;color:#ffffff;text-decoration:none;padding:11px 18px;border-radius:5px;font-size:15px">Continue setup</a>
<p style="font-size:13px;line-height:1.6;color:#55647a;margin:24px 0 0">ShipLock never merges or deploys. Every pull request waits for your click. Questions: support@shiplock.dev.</p>
</td></tr></table></td></tr></table></body></html>`;
  return { subject: "Welcome to ShipLock", text, html };
}

/** Sends the welcome email once, to new accounts only; false when skipped. */
export async function sendWelcomeOnce(user: AuthUser, appUrl: string, now = new Date()): Promise<boolean> {
  if (!user.email || user.app_metadata?.welcome_sent_at) return false;
  const created = user.created_at ? Date.parse(user.created_at) : NaN;
  if (!(now.getTime() - created < NEW_ACCOUNT_MS)) return false;
  const { error } = await getSupabaseAdmin().auth.admin.updateUserById(user.id, {
    app_metadata: { ...user.app_metadata, welcome_sent_at: now.toISOString() },
  });
  if (error) return false;
  return sendEmail({ to: user.email, ...welcomeMessage(appUrl) }, "welcome");
}
