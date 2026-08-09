/**
 * Pretty-prints a raw vendor payload for display.
 *
 * Vendors ship their records as one line of minified JSON, which is what the pipeline
 * stores and therefore what the console showed: a single unbroken string an analyst has
 * to read character by character to find the one field they came for. Indenting it is
 * the whole difference between "the payload is retained" and "the payload is readable".
 *
 * The result is TEXT and stays text — the caller renders it through interpolation, never
 * v-html. Parsing does not change that: `JSON.parse` on a string builds data, it does not
 * evaluate anything, and re-serialising escapes whatever the vendor sent.
 *
 * A payload that is not JSON is returned VERBATIM rather than rejected. Some sources are
 * line-oriented text, and a raw record the console refuses to show is worse than an ugly
 * one. `pretty` tells the caller which happened so it can say so.
 */
export interface FormattedPayload {
  /** The text to display: indented when it parsed, the original otherwise. */
  text: string
  /** True when the payload parsed as JSON and is shown indented. */
  pretty: boolean
}

/**
 * Above this size, formatting is skipped and the payload is shown as sent.
 *
 * Parsing and re-serialising a multi-megabyte record blocks the main thread while the
 * dialog is already open, so the console would freeze on exactly the payloads that are
 * slowest to arrive. Half a megabyte is far above any real WAF record and well below
 * where the cost is noticeable.
 */
const MAX_FORMAT_CHARS = 512 * 1024

export function formatPayload(raw: string | null | undefined): FormattedPayload {
  const text = raw ?? ''
  if (!text.trim() || text.length > MAX_FORMAT_CHARS) {
    return { text, pretty: false }
  }

  try {
    const parsed: unknown = JSON.parse(text)
    // A bare string or number is valid JSON but indenting it produces the same one line
    // with quotes added, which only makes the payload harder to read than it was.
    if (parsed === null || typeof parsed !== 'object') {
      return { text, pretty: false }
    }
    return { text: JSON.stringify(parsed, null, 2), pretty: true }
  } catch {
    // Not JSON — a line-oriented or truncated record. Show what the vendor sent.
    return { text, pretty: false }
  }
}
