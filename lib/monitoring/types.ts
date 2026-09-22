// Shared monitoring types.
//
// These live here rather than in run.ts because the collector registry needs
// them and run.ts imports the registry — keeping them in run.ts would make that
// a cycle. Re-exported from run.ts so every existing import site is unchanged.

export interface MonitoredProfile {
  id: string;
  email: string | null;
  /** Legacy endpoint/app watch switch. Explicit provider connections do not
   * depend on it, but disabled endpoint probing must stay disabled. */
  monitoring_enabled?: boolean;
  monitored_project_url: string | null;
  monitored_anon_key_encrypted: string | null;
  /**
   * The customer's own live app URL, when we have one. Optional because the
   * hourly pass neither needs nor selects it.
   */
  monitored_app_url?: string | null;
  /**
   * Set when the customer connected their database by connection string rather
   * than Supabase OAuth (Neon, Railway, RDS, self-hosted…). Presence is the
   * whole signal — the credential itself is decrypted inside the collector and
   * never travels on the profile.
   */
  postgres_dsn_encrypted?: string | null;
  /**
   * Set when the customer installed the Vercel integration. Presence is the
   * whole signal, same as the Postgres DSN: the token is decrypted inside the
   * collector and never travels on the profile.
   */
  vercel_access_token_encrypted?: string | null;
  vercel_team_id?: string | null;
  /** Read-only Supabase Management connection; the worker rereads the token. */
  supabase_mgmt_token_encrypted?: string | null;
  supabase_mgmt_project_ref?: string | null;
}

export type TriggerSource = "deploy" | "hourly" | "scheduled_48h";
