"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
} from "react";

interface ConceptState {
  activeRepo: string;
  dismissed: string[];
  mergeBlocking: boolean;
  automaticFixes: boolean;
  reportPublic: boolean;
  emailAlerts: boolean;
  databaseConnected: boolean;
  compactMode: boolean;
}

interface ConceptContextValue extends ConceptState {
  update: (patch: Partial<ConceptState>) => void;
  dismiss: (id: string) => void;
  reset: () => void;
  toast: (message: string) => void;
}

const DEFAULT_STATE: ConceptState = {
  activeRepo: "ledgerloop/app",
  dismissed: [],
  mergeBlocking: true,
  automaticFixes: true,
  reportPublic: true,
  emailAlerts: true,
  databaseConnected: false,
  compactMode: false,
};

const ConceptContext = createContext<ConceptContextValue | null>(null);

export function ConceptProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState(DEFAULT_STATE);
  const [message, setMessage] = useState<string | null>(null);

  const update = useCallback((patch: Partial<ConceptState>) => {
    setState((current) => ({ ...current, ...patch }));
  }, []);

  const dismiss = useCallback((id: string) => {
    setState((current) => ({
      ...current,
      dismissed: current.dismissed.includes(id)
        ? current.dismissed
        : [...current.dismissed, id],
    }));
  }, []);

  const reset = useCallback(() => setState(DEFAULT_STATE), []);

  const toast = useCallback((nextMessage: string) => {
    setMessage(nextMessage);
    window.setTimeout(() => {
      setMessage((current) => (current === nextMessage ? null : current));
    }, 2800);
  }, []);

  const value = useMemo(
    () => ({ ...state, update, dismiss, reset, toast }),
    [state, update, dismiss, reset, toast],
  );

  return (
    <ConceptContext.Provider value={value}>
      {children}
      <div className={`cx-toast${message ? " is-visible" : ""}`} role="status" aria-live="polite">
        <span className="cx-status-dot is-bronze" />
        {message}
      </div>
    </ConceptContext.Provider>
  );
}

export function useConcept() {
  const context = useContext(ConceptContext);
  if (!context) throw new Error("useConcept must be used inside ConceptProvider");
  return context;
}
