"use client";

import { createAuthClient } from "better-auth/react";
import { twoFactorClient } from "better-auth/client/plugins";

// Client for the Better Auth 2FA layer. Points at the dedicated /api/2fa base
// path (Supabase owns /api/auth). Only the two-factor surface is used — login
// stays on Supabase. NOTE: enabling 2FA requires a Better Auth session for the
// user, which does not exist yet (users authenticate via Supabase). The
// Supabase->Better Auth identity bridge is the remaining, must-be-tested piece
// — see AGENTS.md. This client compiles against the real SDK types but is
// not wired into the live dashboard until that bridge is built and verified.
export const authClient = createAuthClient({
  baseURL: "/api/2fa",
  plugins: [twoFactorClient()],
});
