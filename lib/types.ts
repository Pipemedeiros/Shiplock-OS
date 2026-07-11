// ShipLock shared types
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type Severity = 'CRITICAL' | 'WARNING' | 'INFO';

export interface PreviewIssue {
  title: string;
  severity: Severity;
  consequence: string;
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
  grade: Grade;
  summary: string;
  isPaid: boolean;
  issues: PreviewIssue[] | FullIssue[];
  appUrlChecked: boolean;
}

export interface UserProfile {
  id: string;
  email: string;
  is_paid: boolean;
  stripe_customer_id?: string;
  monitoring_enabled: boolean;
  monitored_project_url?: string;
  monitor_webhook_token: string;
  bonus_scans: number;
}
