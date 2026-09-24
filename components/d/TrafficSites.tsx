"use client";

// Optional traffic observation, bound to a repository (2F-2b). The snippet in
// the customer's app mirrors minimized request metadata to ShipLock off the
// request path and fails open; traffic never goes through ShipLock. A site's
// token is shown once, inside its snippet.

import { useEffect, useState } from "react";

type Repo = { id: string; fullName: string };
type Site = { siteId: string; host: string; repository: string; createdAt: string };
type Created = { host: string; snippets: { nextjs: string; web: string; express: string } };

const note = { fontSize: 13, color: "var(--muted)", margin: "0 0 10px", maxWidth: 700 } as const;
const pre = { margin: "6px 0 0", fontSize: 11.5, lineHeight: 1.5, maxHeight: 260, overflow: "auto" as const, whiteSpace: "pre" as const,
  background: "var(--paper)", border: "1px solid var(--line)", borderRadius: 6, padding: "10px 12px", userSelect: "all" as const };

export function TrafficSitesView({ enabled, repositories, sites, created, busy, error, onCreate, onRevoke }: {
  enabled: boolean; repositories: Repo[]; sites: Site[]; created: Created | null; busy: boolean; error: string;
  onCreate: (repositoryId: string, host: string) => void; onRevoke: (siteId: string) => void;
}) {
  return (
    <div>
      <p style={note}>
        Optional. A small snippet in your app sends ShipLock request metadata only (path, method, user agent and a
        hashed source id), never request bodies, credentials, or your users&apos; data. Your traffic never goes through
        ShipLock. If ShipLock is down, your app is unaffected. We use it to tell which of a repository&apos;s findings
        are being probed right now. Kept for 48 hours.
      </p>
      <p style={note}>
        If you connected Supabase and linked it to a repository, ShipLock also reads its API request log with nothing to
        install, and stores only the paths suspicious clients hit, never their addresses. With neither the snippet nor a
        connected Supabase project, ShipLock sees no traffic at all, and says so rather than reporting quiet.
      </p>
      {!enabled ? (
        <p style={note}>Traffic observation is not enabled for this account yet.</p>
      ) : repositories.length === 0 ? (
        <p style={note}>Select a repository first; each site is linked to one repository.</p>
      ) : (
        <SiteForm repositories={repositories} busy={busy} onCreate={onCreate} />
      )}
      {error ? <p style={{ ...note, color: "var(--crit)" }}>{error}</p> : null}
      {created ? (
        <div style={{ margin: "10px 0" }}>
          <p style={{ ...note, color: "var(--ink)" }}>Snippet for {created.host}. Copy it now: its token is shown only once.
            For Next.js, save as middleware.ts at the root of your app:</p>
          <pre style={pre}>{created.snippets.nextjs}</pre>
          <details style={{ marginTop: 8 }}><summary style={{ fontSize: 13 }}>Other frameworks (web standard, Express)</summary>
            <pre style={pre}>{created.snippets.web}</pre>
            <pre style={pre}>{created.snippets.express}</pre>
          </details>
        </div>
      ) : null}
      {sites.map((site) => (
        <div key={site.siteId} className="v3-between" style={{ fontSize: 13, padding: "4px 0" }}>
          <span>{site.host} → {site.repository}</span>
          <button type="button" className="v3-btn v3-btn-sm v3-ghost" onClick={() => onRevoke(site.siteId)} disabled={busy}>Revoke</button>
        </div>
      ))}
    </div>
  );
}

function SiteForm({ repositories, busy, onCreate }: { repositories: Repo[]; busy: boolean; onCreate: (repositoryId: string, host: string) => void }) {
  const [repositoryId, setRepositoryId] = useState(repositories[0]?.id ?? "");
  const [host, setHost] = useState("");
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
      <select value={repositoryId} onChange={(e) => setRepositoryId(e.target.value)}>
        {repositories.map((r) => <option key={r.id} value={r.id}>{r.fullName}</option>)}
      </select>
      <input value={host} onChange={(e) => setHost(e.target.value)} placeholder="app.example.com" style={{ flex: 1, minWidth: 180 }} />
      <button type="button" className="v3-btn v3-btn-sm v3-ghost" disabled={busy || !host.trim()}
        onClick={() => onCreate(repositoryId, host.trim())}>Add site</button>
    </div>
  );
}

export function TrafficSites({ enabled, repositories }: { enabled: boolean; repositories: Repo[] }) {
  const [sites, setSites] = useState<Site[]>([]);
  const [created, setCreated] = useState<Created | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // The list is a convenience: a failed read leaves it as it was.
  const fetchSites = () => fetch("/api/traffic/sites")
    .then((res) => (res.ok ? res.json() as Promise<{ sites?: Site[] }> : null))
    .then((data) => { if (data) setSites(data.sites ?? []); }).catch(() => {});
  const load = () => fetchSites();
  useEffect(() => { fetchSites(); }, []);

  async function create(repositoryId: string, host: string) {
    setBusy(true); setError(""); setCreated(null);
    try {
      const res = await fetch("/api/traffic/sites", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ repositoryId, host }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setError(data.error ?? "Could not add the site. Try again."); return; }
      setCreated({ host, snippets: data.snippets });
      await load();
    } catch { setError("Could not reach ShipLock. Try again."); }
    finally { setBusy(false); }
  }

  async function revoke(siteId: string) {
    setBusy(true);
    try { await fetch(`/api/traffic/sites?id=${encodeURIComponent(siteId)}`, { method: "DELETE" }); await load(); }
    finally { setBusy(false); }
  }

  return <TrafficSitesView enabled={enabled} repositories={repositories} sites={sites} created={created} busy={busy}
    error={error} onCreate={create} onRevoke={revoke} />;
}
