"use client";

import { STACK } from "../../data";
import { useProto } from "../../store";

const DEPTH: Record<string, { label: string; cls: string; note: string }> = {
  reasoned: { label: "Reasoned about", cls: "pr-tag-ok", note: "We understand how your code uses it and check it." },
  read: { label: "Read", cls: "pr-tag-mute", note: "Detected and inventoried." },
  offer: { label: "Optional connection", cls: "pr-tag-warn", note: "Not required. Connecting deepens one class of finding." },
};

export default function StackPage() {
  const { toast } = useProto();
  return (
    <>
      <div className="pr-page-hd">
        <div>
          <p className="pr-eyebrow">Your stack</p>
          <h1 className="pr-serif" style={{ marginTop: 8 }}>Read out of your code. Nothing you had to type.</h1>
          <p className="pr-sub" style={{ marginTop: 8, maxWidth: 620 }}>
            This is the whole argument for connecting only GitHub. Your repository already declares
            what your system talks to — the manifests, the imports, the environment variable names,
            the schema. We read the map from there.
          </p>
        </div>
      </div>

      <div className="pr-grid-2">
        {STACK.map((s) => {
          const d = DEPTH[s.depth];
          return (
            <div key={s.name} className="pr-tile">
              <div className="pr-tile-glyph">{s.glyph}</div>
              <div style={{ flex: 1 }}>
                <div className="pr-between">
                  <strong style={{ fontWeight: 500 }}>{s.name}</strong>
                  <span className={`pr-tag ${d.cls}`} title={d.note}>{d.label}</span>
                </div>
                <p className="pr-sub" style={{ fontSize: 13 }}>{s.role}</p>
                <p style={{ fontSize: 13.5, marginTop: 8 }}>{s.note}</p>
                <p className="pr-file" style={{ marginTop: 8 }}>{s.evidence}</p>
                {s.depth === "offer" ? (
                  <button className="pr-btn pr-btn-ghost pr-btn-sm" style={{ marginTop: 10 }}
                    onClick={() => toast(`${s.name} is optional — the product works without it`)}>
                    Connect {s.name}
                  </button>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>

      <div className="pr-card pr-card-p" style={{ marginTop: 18 }}>
        <p className="pr-eyebrow">Where reading the code is not enough</p>
        <p style={{ marginTop: 10, maxWidth: 720 }}>
          A bucket policy, a firewall rule and a production environment variable do not live in your
          repository. Findings that depend on them are labelled <strong>inferred</strong> and stay
          that way. Connecting your database read-only turns a handful of them into{" "}
          <strong>proven</strong> — an upgrade, never a requirement.
        </p>
      </div>
    </>
  );
}
