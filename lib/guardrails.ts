import type { Severity } from "@/lib/types";

// Guardrails for the categories no scanner can reach — business logic, access
// control that depends on app intent, session handling in the customer's own
// code. The only honest lever here is to hand the customer targeted AUDIT
// prompts for their coding agent, framed for someone who ALREADY has a running
// app (not building from scratch). This is the dashboard, actionable version of
// /owasp's "What we can't scan — and what to ask instead" section
// (app/(d)/owasp/page.tsx NOT_SCANNABLE); some prompts are shared verbatim so
// the two stay consistent.

export interface Guardrail {
  id: string;
  surface: string;
  // Why a scanner can't do this and the customer's agent must.
  why: string;
  // Copy-paste prompts for their coding agent. Imperative, specific.
  prompts: string[];
  emphasis: Severity; // ranks the category in the UI
}

export const GUARDRAILS: Guardrail[] = [
  {
    id: "access-control",
    surface: "Broken access control (A01)",
    why:
      "We can see whether your database blocks a stranger. We can't see whether your own API routes check that the logged-in user owns the thing they're changing — that lives in your code, and it's the single most common way vibe-coded apps leak or corrupt data.",
    emphasis: "CRITICAL",
    prompts: [
      "List every API route and server action in this codebase that creates, updates, or deletes a record. For each one, show me the exact line that verifies the current user is allowed to act on that specific record (not just that they're logged in). Flag every route that has no such check.",
      "Find every place I read a user ID, account ID, org ID, or role from the request (body, query, params, or headers) and use it in a database query. For each, confirm the value is verified against the authenticated session — never trusted as sent.",
    ],
  },
  {
    id: "business-logic",
    surface: "Business logic (A04 · Insecure Design)",
    why:
      "No scanner can read your intent — only a human or an AI agent walked through your actual flows can. For every flow that touches money, auth, or another user's data, paste this to your coding agent.",
    emphasis: "CRITICAL",
    prompts: [
      "Walk through [flow name] end to end. For each step: what happens if this request arrives twice? Out of order? From a user who shouldn't be able to reach this step yet? Does the server ever trust a price, role, quantity, or user ID that the client sent, instead of computing or verifying it server-side?",
      "Find any place a total, credit balance, discount, or quantity is calculated using a number that came from the client. Show me where the server recomputes or validates it before it's trusted.",
    ],
  },
  {
    id: "session-jwt",
    surface: "Session & token handling",
    why:
      "We check how your tokens are signed and watch for stolen sessions in use. What we can't see is how your own code stores and clears them — a token kept in localStorage is one XSS away from theft, and a logout that doesn't actually end the session isn't a logout.",
    emphasis: "WARNING",
    prompts: [
      "How does this app store the auth session — localStorage, or httpOnly cookies? If it uses the default @supabase/supabase-js browser client (localStorage), show me what it would take to move to the cookie-based @supabase/ssr client so an XSS can't read the token.",
      "Trace what happens on sign-out. Is the session actually invalidated server-side, and are the auth cookies/tokens cleared? Then: does anything log, or put in a URL or query string, an access token, refresh token, or session cookie? List every occurrence.",
    ],
  },
  {
    id: "integrity",
    surface: "Build & deploy integrity (A08)",
    why:
      "This is about whether what ships is what you reviewed — a pipeline question, not a database one.",
    emphasis: "WARNING",
    prompts: [
      "Review my deploy setup: is there a lockfile committed and enforced (not just present)? Does main auto-deploy without any review step? For every webhook receiver in this codebase (Stripe, GitHub, etc.), confirm the signature is actually verified before the payload is trusted — list any that aren't.",
    ],
  },
  {
    id: "logging",
    surface: "Logging & alerting (A09)",
    why:
      "You don't need a SIEM. You need to know if something changed. Ask your agent to check for the absence of these, not to add anything heavy.",
    emphasis: "INFO",
    prompts: [
      "Does this app log failed login attempts anywhere I'd ever actually look? Is there any alert if signups or database reads spike far above normal in a short window? If a background job or webhook handler throws, does that failure go anywhere besides a Vercel log I'd have to think to check?",
    ],
  },
];
