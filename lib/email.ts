import { Resend } from "resend";

// One place that actually knows whether an email was sent.
//
// The Resend SDK returns `{ data, error }` and does NOT throw on API errors —
// an invalid key, an unverified sending domain, a rate limit, or a rejected
// recipient all RESOLVE, with `error` set and `data` null. Every call site in
// this repo was written as `await send(...).catch(...)` or a try/catch, which
// only ever catches a network-level throw. An API-level failure was invisible.
//
// That mattered because three of the four call sites gate a "don't tell them
// again" state change on the send: the alert dedup log, the traffic alert log,
// and last_digest_sent_at. A silently-failed send still marked the customer as
// notified, so a CRITICAL finding — a leaked service-role key, say — could be
// suppressed for the full 7-day dedup window while the dashboard happily showed
// it. The customer hears nothing and has no way to know they were owed an email.
//
// So: return a boolean that is true only on CONFIRMED success, and let callers
// decide what to skip when it is false. Never throws — a mail outage must not
// fail a monitoring pass, it must only fail to mark the customer as notified.

interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  /** Optional HTML body; `text` stays as the fallback every client can read. */
  html?: string;
}

/**
 * @param context short tag for logs, e.g. "monitoring" / "digest" / "traffic"
 * @returns true only if Resend confirmed the send
 */
export async function sendEmail(message: EmailMessage, context: string): Promise<boolean> {
  const from = process.env.RESEND_FROM_EMAIL;
  const apiKey = process.env.RESEND_API_KEY;

  // Missing config is a real "not sent", not a crash and not a silent success.
  // Reported as such so a misconfigured environment cannot look like delivery.
  if (!apiKey || !from) {
    console.error(`[${context}] email not sent: RESEND_API_KEY or RESEND_FROM_EMAIL is unset`);
    return false;
  }

  try {
    const { error } = await new Resend(apiKey).emails.send({
      from,
      to: message.to,
      subject: message.subject,
      text: message.text,
      ...(message.html ? { html: message.html } : {}),
    });

    if (error) {
      // The case the old code could not see.
      console.error(`[${context}] email rejected by Resend:`, error.message ?? error);
      return false;
    }
    return true;
  } catch (err) {
    // Network-level failure — the only case the old code did catch.
    console.error(`[${context}] email send threw:`, err instanceof Error ? err.message : err);
    return false;
  }
}
