import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV !== "production";

// Next.js dev mode needs 'unsafe-eval' and a websocket connection for HMR;
// production gets the strict policy.
const scriptSrc = isDev ? "'self' 'unsafe-eval'" : "'self'";
const connectSrc = isDev
  ? "'self' ws: https://api.stripe.com https://*.supabase.co"
  : "'self' https://api.stripe.com https://*.supabase.co";

const securityHeaders = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      `script-src ${scriptSrc}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      `connect-src ${connectSrc}`,
      "frame-src https://js.stripe.com https://checkout.stripe.com",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
