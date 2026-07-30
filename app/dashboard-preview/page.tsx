import { redirect } from "next/navigation";

// /dashboard-preview was an investor-facing concept page built against the OLD
// single-page dashboard and the old marketing components — a design the product
// has not looked like since the dashboard was split into four surfaces. It was
// still linked from the landing page as "Product preview", so anyone following
// that link was shown a version of the product that no longer exists.
//
// Kept as a redirect rather than deleted: the URL has been shared, and a 404 is
// a worse answer than the current preview.
export default function DashboardPreviewPage() {
  redirect("/dashboard-demo");
}
