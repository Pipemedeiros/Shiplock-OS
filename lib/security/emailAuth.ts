import type { Severity } from "@/lib/types";

// D12 from CHECK-SPEC.md — SPF, DKIM and DMARC on the customer's domain.
//
// Why a security product cares about DNS records: without them, anyone can send
// email that says it comes from the customer's domain, and it will land in
// inboxes looking legitimate. For this ICP that is not a spam problem, it is an
// account-takeover and invoice-fraud problem. "Reset your password" from
// their own domain is the most effective phish there is, and their users have no
// way to tell. It is also the cheapest thing on this entire list to fix — three
// DNS records, once — which is exactly why leaving it unchecked is indefensible.
//
// PRECISION RULES, because DNS is easy to over-read:
//  - A record we cannot resolve is NOT reported as missing. A DNS timeout is not
//    evidence of absence, and inventing a finding from a network failure is the
//    fastest way to lose trust.
//  - DKIM absence is NEVER reported. DKIM lives at a per-provider selector
//    (`resend._domainkey`, `google._domainkey`, …), so "we found no selector"
//    genuinely cannot distinguish "not configured" from "configured with a
//    selector we didn't guess". We only report a DKIM record we actually FOUND
//    and can see is broken.
//  - SPF lookup limits are only flagged when the DIRECT mechanism count already
//    exceeds the limit, which is unambiguous without recursive resolution.

export interface EmailAuthFinding {
  id: string;
  severity: Severity;
  title: string;
  consequence: string;
}

/** What a resolver must provide. Injected so every classifier is unit-testable. */
export interface TxtResolver {
  (name: string): Promise<string[]>;
}

// ── SPF ────────────────────────────────────────────────────────────────────

/** SPF's own limit: more than 10 DNS-querying mechanisms is a permerror. */
const SPF_LOOKUP_LIMIT = 10;
const SPF_LOOKUP_MECHANISMS = /\b(include:|a[:\s]|a$|mx[:\s]|mx$|ptr|exists:|redirect=)/g;

export function analyzeSpf(domain: string, txt: string[]): EmailAuthFinding[] {
  // Case-insensitive: "v=SPF1" is valid.
  const records = txt.filter((r) => /^v=spf1\b/i.test(r.trim()));

  if (records.length === 0) {
    return [
      {
        id: "email_auth:spf_missing",
        severity: "WARNING",
        title: `${domain} has no SPF record; anyone can send email as you`,
        consequence:
          `There is no SPF record on ${domain}, so nothing tells receiving mail servers which servers are allowed to send as you. ` +
          `Anyone can send email with a From address at your domain, and it can arrive looking genuine. ` +
          `The realistic attack isn't spam, it's a password-reset or invoice email to your own users from your own domain; they have no way to tell it isn't you. ` +
          `Fix: add one TXT record listing your senders and ending in ~all, e.g. "v=spf1 include:_spf.google.com include:amazonses.com ~all".`,
      },
    ];
  }

  // Two SPF records is a permerror: receivers reject BOTH, so a domain that
  // looks doubly-protected is actually unprotected.
  if (records.length > 1) {
    return [
      {
        id: "email_auth:spf_multiple",
        severity: "WARNING",
        title: `${domain} has ${records.length} SPF records, which invalidates all of them`,
        consequence:
          `SPF allows exactly one record per domain. ${domain} publishes ${records.length}, which is a permanent error: receiving servers discard the lot, ` +
          `so your domain is currently unprotected despite looking configured. This usually happens when a second email provider is added and appends its own record instead of merging. ` +
          `Fix: combine them into a single "v=spf1 …" record with every include: from both.`,
      },
    ];
  }

  const record = records[0];
  const findings: EmailAuthFinding[] = [];
  const normalised = record.toLowerCase();

  // `+all` authorises the entire internet — worse than having no record, since
  // it explicitly vouches for every sender.
  if (/[\s^](\+all|all)\s*$/.test(normalised) && !/[~\-?]all\s*$/.test(normalised)) {
    findings.push({
      id: "email_auth:spf_pass_all",
      severity: "CRITICAL",
      title: `${domain}'s SPF record authorises the entire internet (+all)`,
      consequence:
        `${domain}'s SPF record ends in "+all", which tells every receiving server that ANY host on the internet is an authorised sender for your domain. ` +
        `This is worse than having no SPF at all: instead of staying silent, you are actively vouching for spammers and phishers using your name. ` +
        `Change the ending to ~all (softfail) or -all (hardfail).`,
    });
  } else if (/[\s^]\?all\s*$/.test(normalised)) {
    findings.push({
      id: "email_auth:spf_neutral_all",
      severity: "WARNING",
      title: `${domain}'s SPF record is neutral (?all) and enforces nothing`,
      consequence:
        `${domain}'s SPF ends in "?all", which explicitly means "no opinion" about unlisted senders; receivers treat spoofed mail the same as if you had no record. ` +
        `Change it to ~all or -all so the record actually does something.`,
    });
  } else if (!/[~\-+?]all\b/.test(normalised)) {
    findings.push({
      id: "email_auth:spf_no_all",
      severity: "WARNING",
      title: `${domain}'s SPF record has no "all" mechanism`,
      consequence:
        `${domain}'s SPF record doesn't end with an "all" mechanism, so unlisted senders fall through to a neutral result and spoofed mail is not challenged. ` +
        `Add ~all (recommended while you confirm your senders) or -all to the end of the record.`,
    });
  }

  const lookups = (record.match(SPF_LOOKUP_MECHANISMS) ?? []).length;
  if (lookups > SPF_LOOKUP_LIMIT) {
    findings.push({
      id: "email_auth:spf_too_many_lookups",
      severity: "WARNING",
      title: `${domain}'s SPF record exceeds the 10-lookup limit`,
      consequence:
        `SPF allows at most ${SPF_LOOKUP_LIMIT} DNS-querying mechanisms; ${domain}'s record has at least ${lookups} before counting anything nested inside its includes. ` +
        `Over the limit, receivers return a permanent error and stop evaluating: your SPF silently stops working, which is easy to miss because nothing bounces. ` +
        `Fix: remove providers you no longer use, or flatten the includes.`,
    });
  }

  return findings;
}

// ── DMARC ──────────────────────────────────────────────────────────────────

export function analyzeDmarc(domain: string, txt: string[]): EmailAuthFinding[] {
  const record = txt.map((r) => r.trim()).find((r) => /^v=dmarc1\b/i.test(r));

  if (!record) {
    return [
      {
        id: "email_auth:dmarc_missing",
        severity: "WARNING",
        title: `${domain} has no DMARC record`,
        consequence:
          `There is no DMARC record at _dmarc.${domain}. DMARC is what tells receiving servers what to DO about mail that fails your SPF or DKIM checks, without it, ` +
          `each receiver decides for itself and most will deliver the message anyway. It's also the only one of the three that reports back, so today you have no way to know if anyone is spoofing you. ` +
          `Fix: add a TXT record at _dmarc.${domain} of "v=DMARC1; p=none; rua=mailto:you@${domain}" to start collecting reports, then tighten to p=quarantine and p=reject once you've confirmed your own mail passes.`,
      },
    ];
  }

  const policy = /\bp\s*=\s*(none|quarantine|reject)\b/i.exec(record)?.[1]?.toLowerCase();

  if (policy === "none") {
    return [
      {
        id: "email_auth:dmarc_policy_none",
        severity: "WARNING",
        title: `${domain}'s DMARC policy is p=none, so nothing is blocked`,
        consequence:
          `${domain} publishes DMARC with p=none, which means "watch but take no action"; mail that fails authentication is still delivered. ` +
          `This is the correct place to START, since it collects reports without risking your real email, but it stops no spoofing on its own. ` +
          `Once your reports show your legitimate senders passing, move to p=quarantine and then p=reject. If you've been on p=none for months, you are getting the reporting and none of the protection.`,
      },
    ];
  }

  if (!policy) {
    return [
      {
        id: "email_auth:dmarc_no_policy",
        severity: "WARNING",
        title: `${domain}'s DMARC record has no policy tag`,
        consequence:
          `The DMARC record at _dmarc.${domain} is missing the required p= tag, which makes the whole record invalid; receivers ignore it entirely, ` +
          `so you have the appearance of DMARC with none of the effect. Add "p=none" (then tighten) to the record.`,
      },
    ];
  }

  return []; // quarantine or reject — enforcing
}

// ── DKIM ───────────────────────────────────────────────────────────────────

/**
 * Selectors worth probing, covering the providers this ICP actually uses.
 * A miss proves nothing (see the header note), so this list only ever produces
 * findings, never a "missing DKIM" alarm.
 */
export const DKIM_SELECTORS = [
  "resend", // Resend
  "google", // Google Workspace
  "k1", // Mailchimp / Mandrill
  "s1", // SendGrid / generic
  "s2",
  "selector1", // Microsoft 365
  "selector2",
  "mail",
  "default",
  "dkim",
  "postmark",
  "mandrill",
  "sendgrid",
  "zmail",
];

export function analyzeDkim(domain: string, selector: string, txt: string[]): EmailAuthFinding[] {
  const record = txt.map((r) => r.trim()).find((r) => /\bp\s*=/.test(r) || /^v=dkim1\b/i.test(r));
  if (!record) return [];

  // p= present but empty is the documented way to REVOKE a key. If mail is still
  // being signed with it, every message fails DKIM.
  const key = /\bp\s*=\s*([A-Za-z0-9+/=]*)/.exec(record)?.[1] ?? "";
  if (key.length === 0) {
    return [
      {
        id: `email_auth:dkim_revoked:${selector}`,
        severity: "WARNING",
        title: `${domain}'s DKIM key for selector "${selector}" is empty (revoked)`,
        consequence:
          `The DKIM record at ${selector}._domainkey.${domain} has an empty p= value, which is how a key is formally revoked. ` +
          `If anything is still sending signed mail with this selector, every one of those messages fails DKIM, and with a strict DMARC policy, they don't get delivered. ` +
          `Either publish the correct public key or remove the record.`,
      },
    ];
  }

  // Base64 length is a reliable proxy for modulus size: a 1024-bit RSA
  // SubjectPublicKeyInfo is ~216 base64 chars, a 2048-bit one ~392.
  if (key.length < 200) {
    return [
      {
        id: `email_auth:dkim_weak_key:${selector}`,
        severity: "WARNING",
        title: `${domain}'s DKIM key for selector "${selector}" is weak (under 1024 bits)`,
        consequence:
          `The DKIM key at ${selector}._domainkey.${domain} is shorter than 1024 bits. Keys that small are factorable by a motivated attacker, ` +
          `who could then forge signed mail from your domain that passes every authentication check: strictly worse than no DKIM, because it looks verified. ` +
          `Regenerate at 2048 bits in your email provider's dashboard.`,
      },
    ];
  }

  return [];
}

// ── Orchestration ──────────────────────────────────────────────────────────

/** Extracts the registrable domain to check from an app URL. */
export function domainFromUrl(appUrl: string): string | null {
  let host: string;
  try {
    host = new URL(appUrl).hostname.toLowerCase();
  } catch {
    return null;
  }
  if (!host || /^[\d.]+$/.test(host) || host === "localhost") return null;
  // Email auth lives on the registrable domain, and `www` never has its own.
  return host.replace(/^www\./, "");
}

/**
 * Shared-platform hostnames. A customer on `myapp.vercel.app` doesn't control
 * that domain's DNS, so reporting Vercel's SPF setup to them would be both
 * useless and wrong — they cannot act on it, and it isn't their exposure.
 */
const SHARED_HOSTS =
  /(^|\.)(vercel\.app|netlify\.app|pages\.dev|fly\.dev|onrender\.com|railway\.app|herokuapp\.com|github\.io|web\.app|firebaseapp\.com|supabase\.co|workers\.dev|surge\.sh|glitch\.me|replit\.(app|dev))$/;

export function isSharedHost(domain: string): boolean {
  return SHARED_HOSTS.test(domain);
}

/**
 * Runs the full email-auth audit for a domain.
 *
 * Every resolver call is individually guarded: an unresolvable name yields no
 * finding rather than a "missing record" claim, because a DNS failure is not
 * evidence of absence.
 */
export async function auditEmailAuth(
  appUrl: string, resolveTxt: TxtResolver, unread: string[] = [],
): Promise<EmailAuthFinding[]> {
  const domain = domainFromUrl(appUrl);
  if (!domain) return [];
  if (isSharedHost(domain)) return [];

  const findings: EmailAuthFinding[] = [];

  // SPF and DMARC: only classify when the lookup itself succeeded. NXDOMAIN and
  // "no TXT records" both legitimately mean "no record", and both surface here
  // as an empty array — which is what we want. A thrown error does not.
  const [spf, dmarc] = await Promise.all([
    resolveTxt(domain).then(
      (txt) => ({ ok: true as const, txt }),
      () => ({ ok: false as const, txt: [] as string[] })
    ),
    resolveTxt(`_dmarc.${domain}`).then(
      (txt) => ({ ok: true as const, txt }),
      () => ({ ok: false as const, txt: [] as string[] })
    ),
  ]);

  // The resolver maps real absence to []; a throw is an unread lookup.
  if (spf.ok) findings.push(...analyzeSpf(domain, spf.txt));
  else unread.push("email_auth:spf_");
  if (dmarc.ok) findings.push(...analyzeDmarc(domain, dmarc.txt));
  else unread.push("email_auth:dmarc_");

  // DKIM: probe known selectors, report only on ones we FIND and can see are
  // broken. A selector that doesn't resolve is silence, by design.
  const dkim = await Promise.all(
    DKIM_SELECTORS.map((selector) =>
      resolveTxt(`${selector}._domainkey.${domain}`).then(
        (txt) => ({ selector, txt }),
        () => {
          unread.push(`email_auth:dkim_revoked:${selector}`, `email_auth:dkim_weak_key:${selector}`);
          return { selector, txt: [] as string[] };
        }
      )
    )
  );
  for (const { selector, txt } of dkim) {
    if (txt.length > 0) findings.push(...analyzeDkim(domain, selector, txt));
  }

  return findings;
}

/**
 * DNS error codes that are DEFINITIVE PROOF OF ABSENCE rather than a failure to
 * look:
 *   ENODATA  — the name exists, but has no TXT records
 *   ENOTFOUND / NXDOMAIN — the name doesn't exist at all
 * A domain with no SPF record produces exactly these. Everything else
 * (SERVFAIL, ETIMEOUT, ECONNREFUSED, …) genuinely means "we don't know", and
 * must propagate so the caller stays silent instead of inventing a finding.
 *
 * This distinction is the whole check. Node's resolveTxt THROWS for a missing
 * record rather than returning an empty array, so collapsing every rejection
 * into "unknown" made the audit silent for precisely the domains it exists to
 * catch — verified against shiplock.dev, which has neither record and initially
 * produced zero findings.
 */
const ABSENCE_CODES = new Set(["ENODATA", "ENOTFOUND", "NXDOMAIN"]);

export function isAbsenceError(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && ABSENCE_CODES.has(code);
}

/**
 * Default resolver, backed by Node's DNS. TXT records arrive as arrays of
 * string chunks (long records are split at 255 bytes), so each record's chunks
 * are joined back into one string before any pattern is applied — otherwise a
 * long SPF or DKIM record would be silently misread.
 *
 * Returns `[]` for a proven-absent record; rethrows anything that means the
 * lookup itself failed.
 */
export async function nodeTxtResolver(name: string): Promise<string[]> {
  const { resolveTxt } = await import("node:dns/promises");
  try {
    const records = await resolveTxt(name);
    return records.map((chunks) => chunks.join(""));
  } catch (err) {
    if (isAbsenceError(err)) return [];
    throw err;
  }
}
