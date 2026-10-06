"use client";

import { useEffect, useState } from "react";
import { getSupabaseBrowser } from "@/lib/supabaseBrowser";
import { When } from "@/components/v3/When";
import { SignOutButton } from "@/components/sign-out-button";

/**
 * Two-step sign-in with an authenticator app (Supabase MFA, TOTP). The server
 * enforces it (lib/mfa.ts); these screens only enroll a factor and enter a
 * code. The code field is labelled, numeric, fillable by the phone or a
 * password manager, and paste is never blocked.
 */

const field: React.CSSProperties = { font: "500 20px/1.2 var(--dx-font-geist-mono), monospace", letterSpacing: "0.2em",
  padding: "10px 12px", width: "100%", maxWidth: 220, border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--paper)" };
const cleanCode = (value: string) => value.replace(/\D/g, "").slice(0, 6);

function CodeField({ id, code, onCode }: { id: string; code: string; onCode: (code: string) => void }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      <label htmlFor={id} className="v3-small">Code</label>
      <input id={id} name="code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]*" maxLength={6}
        value={code} onChange={(e) => onCode(cleanCode(e.target.value))} style={field} />
    </div>
  );
}

type Authenticator = { id: string; name: string };

export function MfaChallengeView({ state, code, error, factors, factorId, onFactor, onCode, onSubmit }: {
  state: "loading" | "ready" | "verifying" | "unavailable"; code: string; error: string | null;
  factors: Authenticator[]; factorId: string | null; onFactor: (id: string) => void;
  onCode: (code: string) => void; onSubmit: () => void;
}) {
  return (
    <div className="v3-card" style={{ width: "100%", maxWidth: 380 }}>
      <div className="v3-card-p" style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <h1 style={{ fontSize: 20, fontWeight: 500 }}>Enter your code</h1>
        {state === "unavailable" ? (
          <p className="v3-small">We could not confirm your sign-in. <a href="/dashboard">Try again</a>.</p>
        ) : (
          <form onSubmit={(e) => { e.preventDefault(); onSubmit(); }} style={{ display: "flex", flexDirection: "column", gap: 14 }}>
            <p className="v3-small">Open your authenticator app and enter the 6 digit code for ShipLock.</p>
            {factors.length > 1 ? (
              <fieldset style={{ border: 0, padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 6 }}>
                <legend className="v3-small" style={{ marginBottom: 6 }}>Authenticator</legend>
                {factors.map((f) => (
                  <div key={f.id} className="v3-row" style={{ gap: 8, minHeight: 44 }}>
                    <input type="radio" id={`mfa-factor-${f.id}`} name="factor" value={f.id} checked={f.id === factorId}
                      onChange={() => onFactor(f.id)} style={{ width: 18, height: 18 }} />
                    <label htmlFor={`mfa-factor-${f.id}`} className="v3-small">{f.name}</label>
                  </div>
                ))}
              </fieldset>
            ) : null}
            <CodeField id="mfa-code" code={code} onCode={onCode} />
            {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
            <button type="submit" className="v3-btn v3-btn-sm v3-primary" disabled={state !== "ready" || code.length !== 6}>
              {state === "verifying" ? "Checking" : "Verify"}
            </button>
          </form>
        )}
        <div><SignOutButton /></div>
      </div>
    </div>
  );
}

/** The code step after a password, magic link or Google sign-in. */
export function MfaChallenge({ next }: { next: string }) {
  const [state, setState] = useState<"loading" | "ready" | "verifying" | "unavailable">("loading");
  const [factors, setFactors] = useState<Authenticator[]>([]);
  const [factorId, setFactorId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getSupabaseBrowser().auth.mfa.listFactors().then(({ data, error: listError }) => {
      const verified = listError ? [] : verifiedTotp(data?.all ?? []);
      if (!verified.length) { setState("unavailable"); return; }
      setFactors(verified);
      setFactorId(verified[0].id);
      setState("ready");
    }).catch(() => setState("unavailable"));
  }, []);

  async function submit() {
    if (!factorId) return;
    setState("verifying"); setError(null);
    const { error: verifyError } = await getSupabaseBrowser().auth.mfa.challengeAndVerify({ factorId, code });
    if (verifyError) { setError("That code did not work. Check that your phone's clock is right, then try a new code."); setCode(""); setState("ready"); return; }
    // A full load, so the server reads the upgraded (aal2) session cookie.
    window.location.assign(next);
  }

  return <MfaChallengeView state={state} code={code} error={error} factors={factors} factorId={factorId}
    onFactor={(id) => { setFactorId(id); setError(null); }} onCode={setCode} onSubmit={submit} />;
}

type Enrolled = Authenticator & { since: string };
type TwoStepState =
  | { state: "loading" } | { state: "off" } | { state: "unavailable" }
  | { state: "enrolling"; backup: boolean; factorId: string; qr: string; secret: string }
  | { state: "on"; factors: readonly Enrolled[]; removing: string | null };

/** Verified authenticator apps, oldest first, so the first one set up is the default. */
function verifiedTotp(all: { id: string; factor_type: string; status: string; friendly_name?: string; created_at: string; updated_at: string }[]): Enrolled[] {
  return all.filter((f) => f.factor_type === "totp" && f.status === "verified")
    .sort((a, b) => a.created_at.localeCompare(b.created_at))
    .map((f) => ({ id: f.id, name: f.friendly_name || "Authenticator", since: f.updated_at }));
}

const BACKUP_NAME = "ShipLock backup";

export function TwoStepView({ view, code, error, busy, onCode, onStart, onConfirm, onCancel, onAskRemove, onRemove, onKeep }: {
  view: TwoStepState; code: string; error: string | null; busy: boolean; onCode: (code: string) => void;
  onStart: (backup: boolean) => void; onConfirm: () => void; onCancel: () => void;
  onAskRemove: (factorId: string) => void; onRemove: () => void; onKeep: () => void;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {view.state === "loading" ? <p className="v3-small">Loading.</p> : null}
      {view.state === "unavailable" ? <p className="v3-small">Two-step sign-in could not be read. Reload the page to try again.</p> : null}
      {view.state === "off" ? (
        <>
          <p className="v3-small">Off. Add an authenticator app so a stolen password is not enough to open your account.</p>
          <button type="button" className="v3-btn v3-btn-sm v3-primary" style={{ alignSelf: "flex-start" }} onClick={() => onStart(false)} disabled={busy}>Turn on</button>
        </>
      ) : null}
      {view.state === "enrolling" ? (
        <form onSubmit={(e) => { e.preventDefault(); onConfirm(); }} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <p className="v3-small">{view.backup
            ? "Scan this with the authenticator on your second phone or your password manager, then enter the code it shows."
            : "Scan this with your authenticator app (1Password, Google Authenticator, Authy), then enter the code it shows."}</p>
          {/* eslint-disable-next-line @next/next/no-img-element -- a data URL from Supabase, not an optimizable asset */}
          <img src={view.qr} alt="QR code to add ShipLock to your authenticator app" width={176} height={176}
            style={{ background: "#fff", padding: 8, borderRadius: "var(--r)", border: "1px solid var(--line)" }} />
          <p className="v3-small">Or enter this key: <code style={{ overflowWrap: "anywhere" }}>{view.secret}</code></p>
          <CodeField id="mfa-enroll-code" code={code} onCode={onCode} />
          <div className="v3-row" style={{ gap: 8 }}>
            <button type="submit" className="v3-btn v3-btn-sm v3-primary" disabled={busy || code.length !== 6}>Confirm</button>
            <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onCancel} disabled={busy}>Cancel</button>
          </div>
        </form>
      ) : null}
      {view.state === "on" ? <Enabled view={view} busy={busy} onStart={onStart} onAskRemove={onAskRemove} onRemove={onRemove} onKeep={onKeep} /> : null}
      {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
    </div>
  );
}

function Enabled({ view, busy, onStart, onAskRemove, onRemove, onKeep }: {
  view: Extract<TwoStepState, { state: "on" }>; busy: boolean; onStart: (backup: boolean) => void;
  onAskRemove: (factorId: string) => void; onRemove: () => void; onKeep: () => void;
}) {
  const last = view.factors.length === 1;
  return (
    <>
      <p className="v3-small">On since <When at={view.factors[0].since} date />. Signing in asks for a code from your authenticator app.</p>
      <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "flex", flexDirection: "column", gap: 4 }}>
        {view.factors.map((f) => (
          <li key={f.id} className="v3-row" style={{ gap: 8, flexWrap: "wrap", minHeight: 44 }}>
            <span className="v3-small" style={{ color: "var(--ink)" }}>{f.name}</span>
            {view.removing === f.id ? (
              <span role="group" aria-label={last ? "Confirm turning off two-step sign-in" : `Confirm removing ${f.name}`} className="v3-row" style={{ gap: 8 }}>
                <button type="button" className="v3-btn v3-btn-sm v3-ghost" style={{ color: "var(--crit)" }} onClick={onRemove} disabled={busy}>{last ? "Turn off" : "Remove"}</button>
                <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onKeep} disabled={busy}>{last ? "Keep it on" : "Keep it"}</button>
              </span>
            ) : (
              <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={() => onAskRemove(f.id)} disabled={busy}
                aria-label={last ? undefined : `Remove ${f.name}`}>{last ? "Turn off" : "Remove"}</button>
            )}
          </li>
        ))}
      </ul>
      {last ? (
        <>
          <p className="v3-small">If you lose your phone, a backup authenticator on a second phone or in your password manager still lets you in. Without one, write to support@shiplock.dev to reset it.</p>
          <button type="button" className="v3-btn v3-btn-sm v3-ghost" style={{ alignSelf: "flex-start" }} onClick={() => onStart(true)} disabled={busy}>Add a backup</button>
        </>
      ) : null}
    </>
  );
}

/** The account's two-step state, read from Supabase; any failure reads as unavailable. */
function readTwoStep(): Promise<TwoStepState> {
  return getSupabaseBrowser().auth.mfa.listFactors().then(({ data, error }): TwoStepState => {
    if (error || !data) return { state: "unavailable" };
    const factors = verifiedTotp(data.all);
    return factors.length ? { state: "on", factors, removing: null } : { state: "off" };
  }, (): TwoStepState => ({ state: "unavailable" }));
}

/** Settings: enroll, add a backup, confirm, or remove an authenticator.
 * Adding or removing one needs an aal2 session, which every dashboard page
 * already requires once enrolled. */
export function TwoStepCard() {
  const [view, setView] = useState<TwoStepState>({ state: "loading" });
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const auth = () => getSupabaseBrowser().auth.mfa;

  const load = () => readTwoStep().then(setView);
  useEffect(() => { readTwoStep().then(setView); }, []);

  async function run(step: () => Promise<void>) {
    setBusy(true); setError(null);
    try { await step(); } catch { setError("Could not reach ShipLock. Try again."); } finally { setBusy(false); }
  }

  const start = (backup: boolean) => run(async () => {
    // A half-finished setup leaves an unverified factor; clear it first.
    const { data } = await auth().listFactors();
    for (const f of data?.all ?? []) if (f.status !== "verified") await auth().unenroll({ factorId: f.id });
    // Names are unique per account in Supabase.
    const { data: enrolled, error: enrollError } = await auth().enroll({ factorType: "totp", friendlyName: backup ? BACKUP_NAME : "ShipLock" });
    if (enrollError || !enrolled) { setError("Could not start setup. Try again."); return; }
    setCode("");
    setView({ state: "enrolling", backup, factorId: enrolled.id, qr: enrolled.totp.qr_code, secret: enrolled.totp.secret });
  });
  const confirm = () => run(async () => {
    if (view.state !== "enrolling") return;
    const { error: verifyError } = await auth().challengeAndVerify({ factorId: view.factorId, code });
    if (verifyError) { setError("That code did not work. Try the next code your app shows."); setCode(""); return; }
    await load();
  });
  // Cancelling a backup setup returns to the enabled card, not to "off".
  const cancel = () => run(async () => {
    if (view.state === "enrolling") await auth().unenroll({ factorId: view.factorId });
    await load();
  });
  const remove = () => run(async () => {
    if (view.state !== "on" || !view.removing) return;
    const { error: removeError } = await auth().unenroll({ factorId: view.removing });
    if (removeError) { setError("Could not remove it. Sign in again with your code, then retry."); setView({ ...view, removing: null }); return; }
    await load();
  });

  return <TwoStepView view={view} code={code} error={error} busy={busy} onCode={setCode} onStart={start} onConfirm={confirm}
    onCancel={cancel} onAskRemove={(id) => view.state === "on" && setView({ ...view, removing: id })} onRemove={remove}
    onKeep={() => view.state === "on" && setView({ ...view, removing: null })} />;
}
