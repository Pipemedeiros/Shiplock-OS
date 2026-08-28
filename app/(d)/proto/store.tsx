"use client";

import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  useSyncExternalStore,
} from "react";
import { PATHS, type AttackPath } from "./data";

type PathStatus = AttackPath["status"];

interface ProtoState {
  connected: boolean;
  repos: string[];
  auditDone: boolean;
  statuses: Record<string, PathStatus>;
  plan: string;
  billing: "monthly" | "annual";
  reportPublic: boolean;
  blockMerges: boolean;
  slack: boolean;
}

const DEFAULT: ProtoState = {
  connected: false,
  repos: ["ledgerloop/app"],
  auditDone: false,
  statuses: {},
  plan: "startup",
  billing: "annual",
  reportPublic: true,
  blockMerges: true,
  slack: false,
};

const KEY = "shiplock-proto-v1";

interface Ctx extends ProtoState {
  set: (patch: Partial<ProtoState>) => void;
  reset: () => void;
  setStatus: (id: string, status: PathStatus) => void;
  statusOf: (id: string) => PathStatus;
  openPaths: AttackPath[];
  toast: (message: string) => void;
}

const ProtoCtx = createContext<Ctx | null>(null);

function load(): ProtoState {
  if (typeof window === "undefined") return DEFAULT;
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? { ...DEFAULT, ...(JSON.parse(raw) as Partial<ProtoState>) } : DEFAULT;
  } catch {
    // A prototype should never break on a private window.
    return DEFAULT;
  }
}

const noopSubscribe = () => () => {};

export function ProtoProvider({ children }: { children: React.ReactNode }) {
  // Lazily read persisted state on the client. The subtree is held back until
  // after hydration, so the server render and the hydration render agree even
  // though this initialiser has already loaded a different value.
  const [state, setState] = useState<ProtoState>(load);
  const hydrated = useSyncExternalStore(noopSubscribe, () => true, () => false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(KEY, JSON.stringify(state));
    } catch {
      /* ignore */
    }
  }, [state, hydrated]);

  const set = useCallback((patch: Partial<ProtoState>) => {
    setState((s) => ({ ...s, ...patch }));
  }, []);

  const reset = useCallback(() => {
    setState(DEFAULT);
    try {
      window.localStorage.removeItem(KEY);
    } catch {
      /* ignore */
    }
  }, []);

  const setStatus = useCallback((id: string, status: PathStatus) => {
    setState((s) => ({ ...s, statuses: { ...s.statuses, [id]: status } }));
  }, []);

  const toast = useCallback((m: string) => {
    setMessage(m);
    window.setTimeout(() => setMessage((cur) => (cur === m ? null : cur)), 3200);
  }, []);

  const statusOf = useCallback(
    (id: string) => state.statuses[id] ?? PATHS.find((p) => p.id === id)?.status ?? "open",
    [state.statuses],
  );

  const openPaths = useMemo(
    () => PATHS.filter((p) => statusOf(p.id) !== "fixed"),
    [statusOf],
  );

  const value = useMemo<Ctx>(
    () => ({ ...state, set, reset, setStatus, statusOf, openPaths, toast }),
    [state, set, reset, setStatus, statusOf, openPaths, toast],
  );

  return (
    <ProtoCtx.Provider value={value}>
      <div style={{ visibility: hydrated ? undefined : "hidden" }}>{children}</div>
      {message ? <div className="pr-toast">{message}</div> : null}
    </ProtoCtx.Provider>
  );
}

export function useProto(): Ctx {
  const ctx = useContext(ProtoCtx);
  if (!ctx) throw new Error("useProto must be used inside ProtoProvider");
  return ctx;
}
