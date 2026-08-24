// Shared monitoring types.
//
// These live here rather than in run.ts because the collector registry needs
// them and run.ts imports the registry — keeping them in run.ts would make that
// a cycle. Re-exported from run.ts so every existing import site is unchanged.

export interface MonitoredProfile {
  id: string;
  email: string | null;
  monitored_project_url: string;
  monitored_anon_key_encrypted: string;
  /**
   * The customer's own live app URL, when we have one. Optional because the
   * hourly pass neither needs nor selects it.
   */
  monitored_app_url?: string | null;
}

export type TriggerSource = "deploy" | "hourly" | "scheduled_48h";
