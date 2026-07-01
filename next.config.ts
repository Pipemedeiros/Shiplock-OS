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
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
