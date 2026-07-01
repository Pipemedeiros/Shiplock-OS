import { cn } from "@/lib/utils";

export function Logo({ className }: { className?: string }) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <svg viewBox="0 0 32 32" className="size-7 shrink-0" aria-hidden>
        <path
          fill="#ffffff"
          d="M16 2 L28 7 V16 C28 24 22 29 16 30 C10 29 4 24 4 16 V7 Z"
        />
        <path
          fill="#3b82f6"
          d="M13 15 C13 12 14.5 10 16 10 C17.5 10 19 12 19 15 L19 16 L20 16 C20.6 16 21 16.4 21 17 L21 23 C21 23.6 20.6 24 20 24 L12 24 C11.4 24 11 23.6 11 23 L11 17 C11 16.4 11.4 16 12 16 L13 16 Z"
        />
      </svg>
      <span
        className="text-base font-medium text-white"
        style={{ letterSpacing: "0.05em" }}
      >
        ShipLock
      </span>
    </div>
  );
}
