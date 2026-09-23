/**
 * ShipLock-funded model calls outside the first-scan credit (3G-2). AGENTS.md:
 * ShipLock funds one bounded first scan per account, and later model work is
 * the customer's. These paths still exist and each has a deterministic output,
 * so they are OFF unless explicitly turned on. Turning one on is a spending
 * decision (Felipe's), made by setting its flag to exactly "true".
 */
const FLAGS = {
  "graph-narrative": "SHIPLOCK_FUNDED_NARRATIVES",
  "scan-report": "SHIPLOCK_FUNDED_SCAN_REPORT",
} as const;

export function shiplockFundedCallAllowed(purpose: keyof typeof FLAGS): boolean {
  return process.env[FLAGS[purpose]] === "true";
}
