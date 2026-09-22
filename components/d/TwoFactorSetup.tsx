"use client";

// Account-settings UI for enabling TOTP two-factor via the Better Auth layer.
// SCAFFOLD — build/type-verified against the real SDK, but NOT yet wired into
// the dashboard: enabling 2FA needs a Better Auth session for the user, and our
// users authenticate via Supabase. The Supabase->Better Auth identity bridge is
// the remaining must-be-tested piece. Rendered only where
// deliberately mounted, and clearly labeled beta.
import { useState } from "react";
import { authClient } from "@/lib/betterAuthClient";

type Phase = "idle" | "enrolling" | "verifying" | "enabled";

export function TwoFactorSetup() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [password, setPassword] = useState("");
  const [totpUri, setTotpUri] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");

  async function enable() {
    setError("");
    setPhase("enrolling");
    const { data, error } = await authClient.twoFactor.enable({ password });
    if (error) {
      setError(error.message ?? "Could not start 2FA setup.");
      setPhase("idle");
      return;
    }
    setTotpUri(data?.totpURI ?? null);
    setPhase("verifying");
  }

  async function verify() {
    setError("");
    const { error } = await authClient.twoFactor.verifyTotp({ code });
    if (error) {
      setError(error.message ?? "That code didn't match. Try again.");
      return;
    }
    setPhase("enabled");
  }

  async function disable() {
    setError("");
    const { error } = await authClient.twoFactor.disable({ password });
    if (error) {
      setError(error.message ?? "Could not disable 2FA.");
      return;
    }
    setPhase("idle");
    setTotpUri(null);
  }

  return (
    <div className="dxd-surface">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 12 }}>
        <h3 style={{ margin: 0, fontSize: 15 }}>Two-factor authentication</h3>
        <span className="dxd-mono" style={{ fontSize: 10, color: "var(--d-bronze)" }}>beta</span>
      </div>
      <p style={{ margin: "8px 0 14px", fontSize: 12.5, lineHeight: 1.7, color: "var(--d-muted)" }}>
        Add a time-based one-time code (Google Authenticator, 1Password, Authy) on top of your
        password. Your login stays exactly as it is; this adds a second step.
      </p>

      {phase === "idle" && (
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <input
            type="password"
            placeholder="Confirm your password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ fontSize: 13, padding: "7px 10px" }}
          />
          <button type="button" className="dxd-btn dxd-btn-paper" onClick={enable} style={{ fontSize: 12, padding: "6px 14px" }}>
            Enable 2FA
          </button>
        </div>
      )}

      {phase === "verifying" && (
        <div>
          <p style={{ fontSize: 12.5, color: "var(--d-muted)", margin: "0 0 8px" }}>
            Add this secret to your authenticator app, then enter the 6-digit code it shows:
          </p>
          {totpUri && (
            <p className="dxd-mono" style={{ fontSize: 11, wordBreak: "break-all", background: "var(--d-porcelain)", border: "1px solid var(--d-line)", borderRadius: 8, padding: "10px 12px", userSelect: "all" }}>
              {totpUri}
            </p>
          )}
          <div style={{ display: "flex", gap: 10, marginTop: 10 }}>
            <input
              inputMode="numeric"
              placeholder="123456"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              style={{ fontSize: 13, padding: "7px 10px", width: 110 }}
            />
            <button type="button" className="dxd-btn dxd-btn-paper" onClick={verify} style={{ fontSize: 12, padding: "6px 14px" }}>
              Verify & turn on
            </button>
          </div>
        </div>
      )}

      {phase === "enabled" && (
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span className="dxd-chip dxd-chip-verified">2FA on</span>
          <input
            type="password"
            placeholder="Password to disable"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{ fontSize: 13, padding: "7px 10px" }}
          />
          <button type="button" className="dxd-btn dxd-btn-ghost" onClick={disable} style={{ fontSize: 12, padding: "6px 14px" }}>
            Disable
          </button>
        </div>
      )}

      {error && <p style={{ fontSize: 12.5, color: "var(--d-signal)", marginTop: 10 }}>{error}</p>}
    </div>
  );
}
