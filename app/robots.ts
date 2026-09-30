import type { MetadataRoute } from "next";

/**
 * Public marketing pages are indexed. Signed-in areas, the API and the private
 * report links (/verified/<token>, shareable but not public) are not.
 */
export default function robots(): MetadataRoute.Robots {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "https://shiplock.dev";
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: ["/dashboard", "/onboarding", "/auth", "/welcome", "/cancelled", "/api/", "/verified/"],
    },
    sitemap: `${base}/sitemap.xml`,
  };
}
