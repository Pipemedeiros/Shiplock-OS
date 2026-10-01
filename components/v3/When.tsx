"use client";

import { useSyncExternalStore } from "react";

const subscribe = () => () => {};
const OPTIONS: Intl.DateTimeFormatOptions = { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" };

/** A timestamp in the reader's own time zone. Server components render in the
 * host's zone (UTC on Vercel), so the server pass shows UTC, labelled, and the
 * browser replaces it with local time after hydration. */
export function When({ at, date = false }: { at: string; date?: boolean }) {
  const local = useSyncExternalStore(subscribe, () => true, () => false);
  const d = new Date(at);
  const options = date ? { month: "short", day: "numeric" } as const : OPTIONS;
  const text = local ? d.toLocaleString(undefined, options) : `${d.toLocaleString("en-US", { ...options, timeZone: "UTC" })}${date ? "" : " UTC"}`;
  return <time dateTime={at} title={d.toISOString()}>{text}</time>;
}
