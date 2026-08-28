import type { Metadata } from "next";
import "./concept.css";
import { ConceptProvider } from "./store";

export const metadata: Metadata = {
  title: { absolute: "ShipLock — Dashboard concept 02" },
  description: "A display-only dashboard design concept using sample data.",
  robots: { index: false, follow: false },
};

export default function ConceptLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="dxd cx-root">
      <ConceptProvider>{children}</ConceptProvider>
    </div>
  );
}
