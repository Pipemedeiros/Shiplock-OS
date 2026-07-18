# ShipLock

Continuous, enterprise-methodology security monitoring for AI-built apps —
built for founders shipping on Lovable/Bolt/Cursor/v0 with a Supabase backend who
can build but aren't security experts. $49/month, 7-day trial.

The differentiator is continuous depth + honesty, delivered at a consumer price —
not a one-off grade, and **not** an autonomous offensive agent (that direction was
dropped by design).

## What it does
- **Scan** — 16 external checks across auth/access, data exposure, config, and
  injection (`lib/scanner.ts`).
- **Deep layer** — RLS policy-logic detection, source SAST (secrets, dependency
  CVEs, weak crypto, client XSS, injection), and a reasoning pass, via a connected
  GitHub App.
- **Traffic protection** — a fail-open edge mirror + attacker blocklist.
- **Monitoring** — deploy-triggered, hourly critical-check, and 48h deep passes.
- **Fixes** — one reviewable, editable **PR** per finding (migration PR for
  DB/RLS the customer merges; ShipLock never writes prod directly).
- **Verified report** — a shareable security-posture attestation.

## Stack
Next.js 16 (App Router) · TypeScript · Tailwind · Supabase · Stripe · Resend ·
Vercel · PostHog · Anthropic.

## Development
```bash
npm run dev      # local dev server
npm run build    # must pass before commit
npm run lint     # must pass before commit
npm test         # vitest
```

## Docs
- `CLAUDE.md` — architecture, rules, and non-negotiable boundaries (source of truth).
- `ROADMAP.md` — current state, launch checklist, coverage honesty, roadmap.
- `marketing.md` / `marketing-strategy.md` — market research + GTM.
