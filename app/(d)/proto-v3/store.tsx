"use client";

import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  useSyncExternalStore,
} from "react";
import { RISKS, type Risk, type Status } from "./data";

interface State {
  connected: boolean;
  repos: string[];
  auditDone: boolean;
  statuses: Record<string, Status>;
  billing: "monthly" | "annual";
  reportPublic: boolean;
  blockMerges: boolean;
  autoFix: boolean;
  emailAlerts: boolean;
  paused: boolean;
}

const DEFAULT: State = {
  connected: false,
  repos: ["ledgerloop/app", "ledgerloop/workers"],
  auditDone: false,
  statuses: {},
  billing: "annual",
  reportPublic: true,
  blockMerges: true,
  autoFix: true,
  emailAlerts: true,
  paused: false,
};

const KEY = "shiplock-proto-v3";

interface Ctx extends State {
  set: (patch: Partial<State>) => void;
  reset: () => void;
  setStatus: (id: string, status: Status) => void;
  statusOf: (id: string) => Status;
  openRisks: Risk[];
  toast: (message: string) => void;
}

const StoreCtx = createContext<Ctx | null>(null);

function load(): State {
  if (typeof window === "undefined") return DEFAULT;
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? { ...DEFAULT, ...(JSON.parse(raw) as Partial<State>) } : DEFAULT;
  } catch {
    // A prototype must never break in a private window.
    return DEFAULT;
  }
}

const noopSubscribe = () => () => {};

export function StoreProvider({ children }: { children: React.ReactNode }) {
  // Persisted state is read lazily on the client, and the subtree stays hidden
  // until after hydration so the server and hydration renders agree.
  const [state, setState] = useState<State>(load);
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

  const set = useCallback((patch: Partial<State>) => setState((s) => ({ ...s, ...patch })), []);

  const reset = useCallback(() => {
    setState(DEFAULT);
    try {
      window.localStorage.removeItem(KEY);
    } catch {
      /* ignore */
    }
  }, []);

  const setStatus = useCallback((id: string, status: Status) => {
    setState((s) => ({ ...s, statuses: { ...s.statuses, [id]: status } }));
  }, []);

  const toast = useCallback((m: string) => {
    setMessage(m);
    window.setTimeout(() => setMessage((cur) => (cur === m ? null : cur)), 3000);
  }, []);

  const statusOf = useCallback(
    (id: string) => state.statuses[id] ?? RISKS.find((r) => r.id === id)?.status ?? "open",
    [state.statuses],
  );

  const openRisks = useMemo(() => RISKS.filter((r) => statusOf(r.id) !== "fixed"), [statusOf]);

  const value = useMemo<Ctx>(
    () => ({ ...state, set, reset, setStatus, statusOf, openRisks, toast }),
    [state, set, reset, setStatus, statusOf, openRisks, toast],
  );

  return (
    <StoreCtx.Provider value={value}>
      <div style={{ visibility: hydrated ? undefined : "hidden" }}>{children}</div>
      {message ? <div className="v3-toast">{message}</div> : null}
    </StoreCtx.Provider>
  );
}

export function useStore(): Ctx {
  const ctx = useContext(StoreCtx);
  if (!ctx) throw new Error("useStore must be used inside StoreProvider");
  return ctx;
}
