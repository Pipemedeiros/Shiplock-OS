import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "https://shiplock.dev";
  return {
    rules: {
      userAgent: "*",
      allow: "/",
      disallow: [
        "/dashboard",
        "/onboarding",
        "/api/",
        "/design/", // disposable design sandbox — not product pages
        "/dashboard-preview", // investor concept preview, sample data
      ],
    },
    sitemap: `${base}/sitemap.xml`,
  };
}
