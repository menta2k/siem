/**
 * A debounced wrapper: runs `fn` once the calls stop for `delayMs`.
 *
 * Filter boxes need this. Querying on every keystroke sends one request per character
 * and, worse, renders whichever reply arrives last — which is not necessarily the reply
 * for what the user finally typed, so the table can settle on results for a prefix.
 * Waiting for a pause also avoids querying partial values like `149.62.` that match
 * nothing and read as "no results" while the user is still typing.
 */
export interface Debounced<A extends unknown[]> {
  (...args: A): void
  /** Drops a pending call. Needed on unmount so a timer cannot fire into a dead view. */
  cancel(): void
}

export function debounce<A extends unknown[]>(fn: (...args: A) => void, delayMs: number): Debounced<A> {
  let timer: ReturnType<typeof setTimeout> | null = null

  const debounced = (...args: A): void => {
    if (timer !== null) clearTimeout(timer)
    timer = setTimeout(() => {
      timer = null
      fn(...args)
    }, delayMs)
  }

  debounced.cancel = (): void => {
    if (timer !== null) clearTimeout(timer)
    timer = null
  }

  return debounced
}
