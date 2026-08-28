import type { Metadata } from "next";
import "./v3.css";
import { StoreProvider } from "./store";

export const metadata: Metadata = {
  title: "ShipLock — prototype v3",
  description: "Clickable sketch of the GitHub-first product. Demo data only.",
  robots: { index: false, follow: false },
};

export default function ProtoV3Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="v3">
      <StoreProvider>{children}</StoreProvider>
    </div>
  );
}
