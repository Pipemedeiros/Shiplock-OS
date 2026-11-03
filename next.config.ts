import type { NextConfig } from "next";

// Content-Security-Policy is NOT set here — it needs a fresh nonce per
// request (for Next.js's own inline hydration/RSC-streaming scripts to be
// allowed under a strict script-src), and next.config.ts's headers() can't
// vary per request. It's generated and set in middleware.ts instead.
// Setting it here too would make the browser enforce the intersection of
// both policies, silently keeping this stale unnoticed one in effect.
const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Powerful browser features ShipLock never uses, off for every page.
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), browsing-topics=()" },
];

// Routes that drain the job queue can run a proof, which starts the
// embedded replica in a worker thread (lib/proving/embeddedHost.ts). The
// worker script is loaded by path, so it and the PGlite runtime it imports
// are traced explicitly, for these routes only (PGlite is about 13 MB).
export const PROOF_ROUTES = ["/api/jobs/drain", "/api/monitor/github"];
const PROOF_FILES = [
  "./lib/proving/embeddedWorker.mjs",
  "./node_modules/@electric-sql/pglite/package.json",
  "./node_modules/@electric-sql/pglite/dist/*.js",
  "./node_modules/@electric-sql/pglite/dist/pglite.wasm",
  "./node_modules/@electric-sql/pglite/dist/pglite.data",
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // next dev would otherwise append a Next.js rules block to AGENTS.md, which only Felipe edits.
  agentRules: false,
  outputFileTracingIncludes: Object.fromEntries(PROOF_ROUTES.map((route) => [route, PROOF_FILES])),
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
