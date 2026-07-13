import type { MetadataRoute } from "next";

// Public, indexable pages only — session-gated and sandbox routes are
// excluded here and disallowed in app/robots.ts.
export default function sitemap(): MetadataRoute.Sitemap {
  const base = process.env.NEXT_PUBLIC_APP_URL ?? "https://shiplock.dev";
  const pages: { path: string; priority: number }[] = [
    { path: "/", priority: 1 },
    { path: "/owasp", priority: 0.8 },
    { path: "/incidents", priority: 0.8 },
    { path: "/auth", priority: 0.5 },
    { path: "/terms", priority: 0.3 },
    { path: "/privacy", priority: 0.3 },
  ];
  return pages.map(({ path, priority }) => ({
    url: `${base}${path}`,
    changeFrequency: "weekly" as const,
    priority,
  }));
}
