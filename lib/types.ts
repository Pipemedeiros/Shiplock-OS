// ShipLock shared types
export type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

/**
 * Which layers independently confirmed a finding.
 *
 * Lives on PreviewIssue rather than FullIssue on purpose: this is not fix
 * content, so it is safe for a lapsed subscriber to see. Knowing that two
 * layers agree tells you the finding is real; it does not tell you how to fix
 * it, which stays behind the paywall.
 */
export interface IssueCorrelation {
  layers: { label: string; agreed: boolean }[];
  /** Demonstrated on an isolated replica rather than inferred from rules. */
  proven?: boolean;
}

export interface PreviewIssue {
  title: string;
  severity: Severity;
  consequence: string;
  /** Present only on findings the graph reasoner produced. */
  correlation?: IssueCorrelation;
}

export interface FullIssue extends PreviewIssue {
  fix: string;
  codefix?: {
    file: string;
    description: string;
    prompt: string;
  };
}

export interface ScanResponse {
  summary: string;
  isPaid: boolean;
  issues: PreviewIssue[] | FullIssue[];
  appUrlChecked: boolean;
  // False only when enrollment was skipped (service-role key submitted —
  // we never retain admin credentials for background re-scans).
  monitoringEnrolled: boolean;
}

export interface UserProfile {
  id: string;
  email: string;
  is_paid: boolean;
  stripe_customer_id?: string;
  monitoring_enabled: boolean;
  monitored_project_url?: string;
  monitor_webhook_token: string;
  traffic_ingest_token: string;
  bonus_scans: number;
  // Public "ShipLock Verified" share link — unguessable read-only token,
  // off by default (migration 030).
  verified_report_token?: string | null;
  verified_report_enabled?: boolean;
}

// ── Edge traffic protection ────────────────────────────────────────────────
// The customer's middleware snippet mirrors one of these per watched request
// (auth/api paths only). source_id is SHA-256(ip + daily salt) computed at the
// edge — never a raw IP. No bodies, no query strings.
export interface TrafficEvent {
  source_id: string;
  path: string;
  method: string;
  ua: string | null;
  // Salted hash of the session token (never the raw token). Null for
  // anonymous requests. Drives session-hijack detection (one session seen
  // from many sources).
  session_id?: string | null;
  t: number; // client-side epoch ms, advisory only — server uses created_at
  /** The attack pattern the customer's snippet classified locally, if any. */
  probe?: "sqli" | "traversal" | "xss" | "ssrf" | "cmdi" | "nosql" | null;
}

export type TrafficAction = "block" | "alert" | "none";

// Output of the pure detector (lib/traffic/detect.ts). ttlMs only meaningful
// when action === "block".
export interface Decision {
  action: TrafficAction;
  reason: string;
  severity: Severity;
  ttlMs: number;
}

// A currently-active block, as surfaced on the dashboard (metadata only).
export interface BlockedSource {
  sourceId: string;
  reason: string;
  severity: Severity;
  blockedAt: string;
  expiresAt: string;
}

// Dashboard protection status — is the snippet installed and talking to us,
// and the token needed to render the install snippet.
export interface ProtectionStatus {
  installed: boolean;
  lastSeenAt: string | null;
  activeBlocks: number;
  ingestToken: string | null;
}
