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

export function MfaChallengeView({ state, code, error, onCode, onSubmit }: {
  state: "loading" | "ready" | "verifying" | "unavailable"; code: string; error: string | null;
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
  const [factorId, setFactorId] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getSupabaseBrowser().auth.mfa.listFactors().then(({ data, error: listError }) => {
      const factor = listError ? undefined : data?.all.find((f) => f.factor_type === "totp" && f.status === "verified");
      if (!factor) { setState("unavailable"); return; }
      setFactorId(factor.id);
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

  return <MfaChallengeView state={state} code={code} error={error} onCode={setCode} onSubmit={submit} />;
}

type TwoStepState =
  | { state: "loading" } | { state: "off" } | { state: "unavailable" }
  | { state: "enrolling"; factorId: string; qr: string; secret: string }
  | { state: "on" | "confirm_off"; factorId: string; since: string };

export function TwoStepView({ view, code, error, busy, onCode, onStart, onConfirm, onCancel, onAskOff, onOff, onKeep }: {
  view: TwoStepState; code: string; error: string | null; busy: boolean; onCode: (code: string) => void;
  onStart: () => void; onConfirm: () => void; onCancel: () => void; onAskOff: () => void; onOff: () => void; onKeep: () => void;
}) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {view.state === "loading" ? <p className="v3-small">Loading.</p> : null}
      {view.state === "unavailable" ? <p className="v3-small">Two-step sign-in could not be read. Reload the page to try again.</p> : null}
      {view.state === "off" ? (
        <>
          <p className="v3-small">Off. Add an authenticator app so a stolen password is not enough to open your account.</p>
          <button type="button" className="v3-btn v3-btn-sm v3-primary" style={{ alignSelf: "flex-start" }} onClick={onStart} disabled={busy}>Turn on</button>
        </>
      ) : null}
      {view.state === "enrolling" ? (
        <form onSubmit={(e) => { e.preventDefault(); onConfirm(); }} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <p className="v3-small">Scan this with your authenticator app (1Password, Google Authenticator, Authy), then enter the code it shows.</p>
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
      {view.state === "on" || view.state === "confirm_off" ? (
        <>
          <p className="v3-small">On since <When at={view.since} date />. Signing in asks for a code from your authenticator app. If you lose your phone, write to support@shiplock.dev to reset it.</p>
          {view.state === "on" ? (
            <button type="button" className="v3-btn v3-btn-sm v3-ghost" style={{ alignSelf: "flex-start" }} onClick={onAskOff} disabled={busy}>Turn off</button>
          ) : (
            <span role="group" aria-label="Confirm turning off two-step sign-in" className="v3-row" style={{ gap: 8 }}>
              <button type="button" className="v3-btn v3-btn-sm v3-ghost" style={{ color: "var(--crit)" }} onClick={onOff} disabled={busy}>Turn off</button>
              <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onKeep} disabled={busy}>Keep it on</button>
            </span>
          )}
        </>
      ) : null}
      {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
    </div>
  );
}

/** The account's two-step state, read from Supabase; any failure reads as unavailable. */
function readTwoStep(): Promise<TwoStepState> {
  return getSupabaseBrowser().auth.mfa.listFactors().then(({ data, error }): TwoStepState => {
    if (error || !data) return { state: "unavailable" };
    const on = data.all.find((f) => f.factor_type === "totp" && f.status === "verified");
    return on ? { state: "on", factorId: on.id, since: on.updated_at } : { state: "off" };
  }, (): TwoStepState => ({ state: "unavailable" }));
}

/** Settings: enroll, confirm, or remove the authenticator. Removing needs an
 * aal2 session, which every dashboard page already requires once enrolled. */
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

  const start = () => run(async () => {
    // A half-finished setup leaves an unverified factor; clear it first.
    const { data } = await auth().listFactors();
    for (const f of data?.all ?? []) if (f.status !== "verified") await auth().unenroll({ factorId: f.id });
    const { data: enrolled, error: enrollError } = await auth().enroll({ factorType: "totp", friendlyName: "ShipLock" });
    if (enrollError || !enrolled) { setError("Could not start setup. Try again."); return; }
    setCode("");
    setView({ state: "enrolling", factorId: enrolled.id, qr: enrolled.totp.qr_code, secret: enrolled.totp.secret });
  });
  const confirm = () => run(async () => {
    if (view.state !== "enrolling") return;
    const { error: verifyError } = await auth().challengeAndVerify({ factorId: view.factorId, code });
    if (verifyError) { setError("That code did not work. Try the next code your app shows."); setCode(""); return; }
    await load();
  });
  const cancel = () => run(async () => {
    if (view.state === "enrolling") await auth().unenroll({ factorId: view.factorId });
    setView({ state: "off" });
  });
  const off = () => run(async () => {
    if (view.state !== "confirm_off") return;
    const { error: offError } = await auth().unenroll({ factorId: view.factorId });
    if (offError) { setError("Could not turn it off. Sign in again with your code, then retry."); setView({ ...view, state: "on" }); return; }
    await load();
  });

  return <TwoStepView view={view} code={code} error={error} busy={busy} onCode={setCode} onStart={start} onConfirm={confirm}
    onCancel={cancel} onAskOff={() => view.state === "on" && setView({ ...view, state: "confirm_off" })} onOff={off}
    onKeep={() => view.state === "confirm_off" && setView({ ...view, state: "on" })} />;
}
