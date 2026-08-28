import type { Metadata } from "next";
import "./proto.css";
import { ProtoProvider } from "./store";

export const metadata: Metadata = {
  title: "ShipLock — product prototype",
  description: "Clickable sketch of the GitHub-only product experience. Demo data only.",
  robots: { index: false, follow: false },
};

export default function ProtoLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="pr-root">
      <ProtoProvider>{children}</ProtoProvider>
    </div>
  );
}
