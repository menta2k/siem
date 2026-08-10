/**
 * How this console renders a moment in time.
 *
 * Every timestamp shown to an analyst goes through here, and that is the point rather
 * than tidiness. A SIEM is read alongside other consoles — Cloudflare's, the appliance's,
 * a ticket someone opened — and the whole job is deciding whether two records describe
 * the same request. Two clocks in one investigation is how a real correlation gets
 * dismissed as unrelated, so the console renders ONE clock and says which one it is.
 *
 * The stored data is untouched by any of this. Events carry UTC instants; a preference
 * changes the projection, never the value.
 */

/** Hour presentation, or "whatever this locale does". */
export type HourFormat = 'auto' | '12' | '24'

/** How timestamps are rendered. */
export interface TimeFormat {
  /** An IANA zone such as "Europe/Sofia", or "" for the browser's own. */
  timeZone: string
  hourFormat: HourFormat
}

/**
 * The default: whatever the browser already does.
 *
 * Chosen so nothing changes appearance until someone deliberately changes it. An
 * analyst's machine is already set to the timezone they think in.
 */
export const BROWSER_DEFAULT: TimeFormat = { timeZone: '', hourFormat: 'auto' }

/**
 * Resolves the zone actually in use, so the console can NAME it.
 *
 * A timestamp with no zone beside it is ambiguous exactly when it matters most — at a
 * handover, in a ticket, next to a vendor's console in another zone.
 */
export function resolveTimeZone(format: TimeFormat): string {
  if (format.timeZone) return format.timeZone
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    // Intl is present in every browser this console supports; the guard exists because
    // a resolvedOptions() failure must not take a page down over a label.
    return 'UTC'
  }
}

/** Builds the Intl options for a preference. */
function optionsFor(format: TimeFormat, base: Intl.DateTimeFormatOptions) {
  const options: Intl.DateTimeFormatOptions = { ...base }
  if (format.timeZone) options.timeZone = format.timeZone
  // `hour12` is left UNSET for 'auto' rather than set to a guess: unset means the
  // locale decides, which is what an analyst who has expressed no preference expects.
  if (format.hourFormat === '12') options.hour12 = true
  if (format.hourFormat === '24') options.hour12 = false
  return options
}

const DATE_TIME: Intl.DateTimeFormatOptions = {
  year: 'numeric',
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
}

/**
 * Renders an instant as a full date and time.
 *
 * Returns the placeholder for anything unparseable — an absent field, or a malformed
 * one. A table cell reading "—" is honest; one reading "Invalid Date" looks like the
 * console is broken, and the analyst cannot tell which of the two it is.
 */
export function formatDateTime(
  value: string | number | Date | null | undefined,
  format: TimeFormat = BROWSER_DEFAULT,
  placeholder = '—',
): string {
  const date = toDate(value)
  if (!date) return placeholder

  try {
    return new Intl.DateTimeFormat(undefined, optionsFor(format, DATE_TIME)).format(date)
  } catch {
    // An invalid IANA zone reaches Intl as a RangeError. Falling back to the browser's
    // own rendering keeps the timestamp readable while the preference is repaired.
    return date.toLocaleString()
  }
}

const TIME_ONLY: Intl.DateTimeFormatOptions = {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
}

/** Renders the time of day only, for axes and other places the date is already known. */
export function formatTimeOfDay(
  value: string | number | Date | null | undefined,
  format: TimeFormat = BROWSER_DEFAULT,
  placeholder = '—',
): string {
  const date = toDate(value)
  if (!date) return placeholder

  try {
    return new Intl.DateTimeFormat(undefined, optionsFor(format, TIME_ONLY)).format(date)
  } catch {
    return date.toLocaleTimeString()
  }
}

/** Parses whatever the API or a caller supplied, rejecting what cannot be a moment. */
function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value === null || value === undefined || value === '') return null

  const date = value instanceof Date ? value : new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
}

/**
 * The zones offered in the picker.
 *
 * A short list rather than the full IANA database: the console is used from a handful of
 * places, and scrolling 400 zone names to find the one you are already in is worse than
 * typing it. UTC is first because it is what the stored data uses, and an auditor
 * comparing against raw logs wants exactly that.
 */
export const COMMON_TIME_ZONES = [
  'UTC',
  'Europe/Sofia',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Moscow',
  'America/New_York',
  'America/Chicago',
  'America/Los_Angeles',
  'Asia/Dubai',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
] as const

/** Reports whether a zone is one Intl accepts, so a bad value never reaches a render. */
export function isValidTimeZone(zone: string): boolean {
  if (!zone) return true // the browser's own zone
  try {
    new Intl.DateTimeFormat(undefined, { timeZone: zone })
    return true
  } catch {
    return false
  }
}
