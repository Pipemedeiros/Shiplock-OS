import type { ProvingHost } from "./arena";

// The legacy monitoring caller still requests a host. Hosted management writes
// are prohibited; only the explicitly authorized embedded proof worker runs.
export function provingHost(): ProvingHost | null {
  return null;
}
