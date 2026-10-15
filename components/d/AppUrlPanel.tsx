"use client";

// The address the outside view reads (G3). GitHub's homepage is offered; the
// founder confirms. ShipLock then fetches what the app serves to anyone, read
// only, as a visitor would, and a confirm starts that read at once.

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

type Suggestion = { repository: string; url: string };
const note = { fontSize: 13, color: "var(--muted)", margin: "0 0 10px", maxWidth: 700 } as const;

export function AppUrlView({ current, suggestions, busy, saved, error, onSave, onClear }: {
  current: string | null; suggestions: Suggestion[]; busy: boolean; saved: boolean; error: string;
  onSave: (url: string) => void; onClear: () => void;
}) {
  // The panel remounts this view when the confirmed address changes (key).
  const [value, setValue] = useState(current ?? "");
  const pending = busy ? <><Loader2 size={14} className="v3-spin" aria-hidden="true" /> Saving</> : null;

  return (
    <div>
      <p style={note}>
        The address your users open. ShipLock reads what it serves to anyone: the JavaScript it ships, and files such
        as /.git or a database dump that should never be public. It sends only the plain requests a page load makes,
        as any visitor would, and never signs in or writes. If your host&apos;s firewall challenges ShipLock, the check
        is shown as not read, never as clean.
      </p>

      {current ? (
        <div className="v3-between" style={{ fontSize: 13.5, marginBottom: 10 }}>
          <span>ShipLock reads {current}</span>
          <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={onClear} disabled={busy}>Stop reading it</button>
        </div>
      ) : null}

      {suggestions.map((s) => (
        <div key={s.url} className="v3-between" style={{ fontSize: 13.5, marginBottom: 8 }}>
          <span>{s.url} <small style={{ color: "var(--muted)" }}>from {s.repository} on GitHub</small></span>
          <button type="button" className="v3-btn v3-btn-sm v3-primary" onClick={() => onSave(s.url)} disabled={busy}
            aria-busy={busy || undefined}>{pending ?? "Use this address"}</button>
        </div>
      ))}

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <label htmlFor="app-url" className="v3-small">App address</label>
        <input id="app-url" value={value} onChange={(e) => setValue(e.target.value)} placeholder="https://app.example.com"
          inputMode="url" autoComplete="url" style={{ flex: 1, minWidth: 200 }} />
        <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy || !value.trim()}
          aria-busy={busy || undefined} onClick={() => onSave(value.trim())}>{pending ?? (current ? "Change" : "Save")}</button>
      </div>

      <p role="status" className="v3-small" style={{ marginTop: 8 }}>{saved && current ? "Saved. Reading your app now; results appear in Issues and Coverage." : ""}</p>
      {error ? <p role="alert" className="v3-small" style={{ color: "var(--crit)" }}>{error}</p> : null}
    </div>
  );
}

export function AppUrlPanel() {
  const [state, setState] = useState<{ current: string | null; suggestions: Suggestion[] }>({ current: null, suggestions: [] });
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/api/app-url").then((r) => (r.ok ? r.json() : null)).then((json) => { if (json) setState(json); }).catch(() => {});
  }, []);

  const send = async (method: "POST" | "DELETE", url?: string) => {
    setBusy(true); setError(""); setSaved(false);
    try {
      const res = await fetch("/api/app-url", { method, headers: { "Content-Type": "application/json" },
        ...(url ? { body: JSON.stringify({ url }) } : {}) });
      const json = (await res.json()) as { url?: string | null; error?: string };
      if (!res.ok) throw new Error(json.error ?? "Could not save your app's address.");
      setState((s) => ({ current: json.url ?? null, suggestions: s.suggestions.filter((x) => x.url !== json.url) }));
      setSaved(method === "POST");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save your app's address.");
    } finally {
      setBusy(false);
    }
  };

  return <AppUrlView key={state.current ?? ""} {...state} busy={busy} saved={saved} error={error} onSave={(url) => void send("POST", url)} onClear={() => void send("DELETE")} />;
}
