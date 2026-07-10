import { redirect } from "next/navigation";

// DESIGN EXPLORATION — only direction D was kept; A/B/C were dropped.
export default function DesignIndex() {
  redirect("/design/d");
}
