import type { ProviderCommit } from "@/lib/monitoring/registry";
import { probeExposedPaths, type ExposedFinding } from "./exposedPaths";
import { auditShippedBundle } from "./bundleAudit";
import { auditResponseHeaders } from "./responseHeaders";
import { MAX_PATHS, type ShippedRead } from "./shippedCalls";
import { readCertificateNames } from "./certificateNames";
import { auditEmailAuth, nodeTxtResolver, domainFromUrl, isSharedHost } from "./emailAuth";
import { analyzeOriginPosture, collectOriginPosture, fetchOriginHeaders, nodeDnsResolver } from "./originExposure";

// Everything we can learn from the customer's app URL alone, in one pass:
//  - exposed-path probes (.git, database dumps, credential files)
//  - the shipped bundle audit (D6 source maps, D7 secrets in public JS)
//  - email authentication on their domain (D12 SPF/DKIM/DMARC)
//  - origin exposure: whether their edge protection can be bypassed
//  - response headers: frame protection and HTTPS pinning (INFO)
// Both take the same single input and hit the same host, so they share a pass
// and a source label. Findings commit through the monitor worker's fence into
// deep_findings (source='exposed-path')
// and flow into the dashboard fix list, the agent brief, MCP, and the Verified
// report counts with no extra wiring.
//
// ARCHIVING: this pass archives findings that no longer reproduce, which it did
// not used to do. That omission mattered most for exactly these checks. A D7
// finding's entire instruction is "rotate this key" — if the finding survived
// the rotation, we'd keep showing CRITICAL after the customer did the one thing
// we asked, and the weekly digest would keep counting it. A check that can't say
// "fixed" is worse than no check: it teaches people that our findings don't
// track reality.
export async function runExposedPathScan(
  userId: string,
  appUrl: string,
  { signal, commit }: { signal?: AbortSignal; commit: ProviderCommit },
): Promise<{ total: number; newCount: number; newFindings: ExposedFinding[] }> {
  // Independent: a failure in one must not cost us the other's findings. Each
  // records the finding-ID prefixes it could not verify in `unread`; a probe
  // that throws outright leaves its whole family unread.
  const unread: string[] = [];
  const failed = (prefix: string) => () => { unread.push(prefix); return []; };
  const shipped: ShippedRead = { pageRead: false, pagesRead: 0, scriptsSeen: 0, scriptsRead: 0, paths: new Set(), requests: new Set() };
  const [paths, bundle, email, origin, certificateNames, headers] = await Promise.all([
    probeExposedPaths(appUrl, signal, unread).catch(failed("exposed:")),
    auditShippedBundle(appUrl, signal, unread, shipped).catch(failed("bundle:")),
    auditEmailAuth(appUrl, nodeTxtResolver, unread).catch(failed("email_auth:")),
    // Origin exposure. Skipped on shared platform hostnames for the same reason
    // as email auth: the customer does not control that DNS, so a finding there
    // is something they cannot act on.
    (async () => {
      const domain = domainFromUrl(appUrl);
      if (!domain || isSharedHost(domain)) return [];
      const headers = await fetchOriginHeaders(appUrl, signal);
      if (!headers) unread.push("origin:");
      const posture = await collectOriginPosture(domain, nodeDnsResolver, headers, unread);
      return posture ? analyzeOriginPosture(posture) : [];
    })().catch(failed("origin:")),
    // Other names on the founder's own domain (certificate transparency):
    // listed for review, never read. null is not read; undefined, not applicable.
    readCertificateNames(appUrl, signal).catch(() => null),
    // Frame protection and HTTPS pinning on the home page (INFO).
    auditResponseHeaders(appUrl, signal, unread).catch(failed("headers:")),
  ]);
  // Probes resolve to [] on network failure, and an empty pass archives every
  // active finding below. A cancelled pass must therefore write nothing at all.
  signal?.throwIfAborted();
  const findings = [...paths, ...bundle, ...email, ...origin, ...headers];

  // Findings commit under the monitor job's lease and the app URL it probed
  // (3F-C2c); unread families are never archived. The fenced commit does not
  // report an archive count, so none is claimed here.
  // The paths the live site names (P5), kept only from a read page: a failed
  // read sends no fact, so the last observation stands with its own time.
  const facts = shipped.pageRead ? { facts: { appSurface: { url: appUrl, pagesRead: shipped.pagesRead, scriptsSeen: shipped.scriptsSeen,
    scriptsRead: shipped.scriptsRead, paths: [...shipped.paths].sort().slice(0, MAX_PATHS),
    requests: [...shipped.requests].sort().slice(0, MAX_PATHS),
    ...(certificateNames !== undefined ? { certificateNames } : {}) } } } : {};
  const created = await commit({ transport: "app-surface", identity: appUrl, ...facts, findings, retire: true, unread,
    snapshot: { scope: new URL(appUrl).host, failed: unread } });
  return { total: findings.length, newCount: created.length, newFindings: created as ExposedFinding[] };
}
