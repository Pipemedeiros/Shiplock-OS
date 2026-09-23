/**
 * A request signal that fires on the transport's own timeout or when the
 * caller (e.g. the monitoring registry) cancels, whichever comes first.
 * Cancelling a read is not a write fence; callers still check before persisting.
 */
export function requestSignal(parent: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return parent ? AbortSignal.any([parent, timeout]) : timeout;
}
