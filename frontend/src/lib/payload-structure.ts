/**
 * Turns a raw vendor payload into fields a person can read.
 *
 * The console used to show every payload as one `<pre>` of whatever the vendor sent,
 * indented when it happened to be JSON. That covered Cloudflare and nginx, which ship
 * NDJSON — and did nothing at all for F5, whose records are syslog: a priority, a
 * timestamp, a host, and then fifty `key="value"` pairs on ONE 2.7 KB line, with a whole
 * escaped HTTP request buried in the middle of it. `JSON.parse` fails, the payload comes
 * back verbatim, and the analyst reads a wall of text character by character looking for
 * the one field they opened the event for.
 *
 * So the shape is detected rather than assumed, and both shapes reduce to the same thing:
 * a flat list of path/value fields. That is what makes one viewer able to filter, hide the
 * padding, and blow up a nested value, whichever vendor sent the record.
 *
 * NOTHING here decodes into markup. Values stay strings and the caller interpolates them,
 * so a payload containing HTML still renders as the characters the vendor sent — the whole
 * point of keeping the raw record (FR-005).
 */

/** How the payload turned out to be encoded. */
export type PayloadShape = 'json' | 'fields' | 'text'

/**
 * What a field's value is, which decides how it is rendered.
 *
 * `empty` is its own kind because vendors pad. Two thirds of an F5 record is `N/A` — a
 * field the appliance has nothing to say about — and folding those away is the single
 * biggest difference between fifty rows and the fifteen that carry information.
 */
export type FieldKind = 'empty' | 'json' | 'block' | 'list' | 'text'

export interface PayloadField {
  /** Dotted path for JSON, the bare key for a key/value record. */
  path: string
  /** Display value: unescaped, and re-indented when it is nested JSON. */
  value: string
  kind: FieldKind
  /** Split parts, for `list` — a comma-separated set the vendor packed into one value. */
  items?: string[]
}

export interface StructuredPayload {
  shape: PayloadShape
  /** The parsed fields, empty when the payload could not be structured. */
  fields: PayloadField[]
  /**
   * The transport envelope a syslog line carries before its fields — priority, time,
   * host, tag. Kept apart from `fields` because it describes the DELIVERY, not the
   * request, and mixing the two invites reading a relay's clock as the event's.
   */
  envelope: PayloadField[]
  /** The payload exactly as received. Always populated; the raw view renders it. */
  raw: string
  /** How many fields were dropped as empty padding, for an honest "showing N of M". */
  emptyCount: number
}

/**
 * Above this size the payload is shown as received and never parsed.
 *
 * Structuring a multi-megabyte record blocks the main thread while the dialog is already
 * open, so the console would freeze on exactly the payloads that were slowest to arrive.
 */
const MAX_PARSE_CHARS = 512 * 1024

/** Guards against a pathological nesting depth flattening into thousands of rows. */
const MAX_DEPTH = 6

/** Values a vendor writes to mean "nothing to report here". */
const EMPTY_VALUES = new Set(['', 'n/a', 'na', '-', 'none', 'null', 'undefined'])

/**
 * Fields whose value is a comma-separated set rather than one string.
 *
 * F5 packs every violation on a blocked request into one value — "Illegal request
 * length,Illegal URL length,Illegal file type" — which is three findings displayed as one
 * sentence. Splitting is by NAME, not by "contains a comma": a user agent and an
 * x-forwarded-for chain both contain commas and neither is a list.
 */
const LIST_FIELDS = new Set([
  'violations',
  'sub_violations',
  'attack_type',
  'sig_ids',
  'sig_names',
  'sig_cves',
  'staged_sig_ids',
  'staged_sig_names',
  'staged_sig_cves',
  'threat_campaign_names',
  'staged_threat_campaign_names',
])

/** Matches `key="value"`, honouring backslash escapes so a quoted body cannot end it early. */
const PAIR_PATTERN = /([A-Za-z0-9_.-]+)="((?:[^"\\]|\\.)*)"/g

/** Matches a syslog envelope: `<134>Aug 16 09:00:36 host ASM:`. */
const SYSLOG_PATTERN = /^<(\d{1,3})>(\w{3}\s+\d{1,2}\s[\d:]{8})\s+(\S+)\s+([A-Za-z0-9_-]+):/

/** RFC 5424 facility names, indexed by the facility number. */
const FACILITIES = [
  'kern',
  'user',
  'mail',
  'daemon',
  'auth',
  'syslog',
  'lpr',
  'news',
  'uucp',
  'cron',
  'authpriv',
  'ftp',
  'ntp',
  'audit',
  'alert',
  'clock',
  'local0',
  'local1',
  'local2',
  'local3',
  'local4',
  'local5',
  'local6',
  'local7',
]

/** RFC 5424 severity names, indexed by the severity number. */
const SEVERITIES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']

/**
 * Undoes the escaping a vendor applied to fit a value on one line.
 *
 * F5 sends an entire HTTP request inside `request="..."` with its CRLFs written as the
 * two characters backslash-n. Left alone it renders as one line with `\r\n` sprinkled
 * through it; undone, it is the request, with its headers where headers go.
 */
export function unescapeValue(value: string): string {
  return value.replace(/\\(.)/g, (match, char: string) => {
    switch (char) {
      case 'n':
        return '\n'
      case 'r':
        return '\r'
      case 't':
        return '\t'
      case '"':
        return '"'
      case '\\':
        return '\\'
      default:
        // An escape this function does not know is left exactly as the vendor wrote it.
        // Silently eating the backslash would change the evidence.
        return match
    }
  })
}

/** Classifies a value and normalises it for display. */
function toField(path: string, rawValue: string): PayloadField {
  const value = unescapeValue(rawValue).replace(/\r\n/g, '\n').trimEnd()

  if (EMPTY_VALUES.has(value.trim().toLowerCase())) {
    return { path, value, kind: 'empty' }
  }

  const key = path.split('.').pop() ?? path
  if (LIST_FIELDS.has(key) && value.includes(',')) {
    const items = value
      .split(',')
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
    if (items.length > 1) return { path, value, kind: 'list', items }
  }

  const nested = asNestedJson(value)
  if (nested) return { path, value: nested, kind: 'json' }

  if (value.includes('\n')) return { path, value, kind: 'block' }

  return { path, value, kind: 'text' }
}

/**
 * Re-indents a value that is itself JSON, or returns null when it is not.
 *
 * Vendors nest JSON inside a string field routinely — Cloudflare's `EdgeResponseHeaders`,
 * F5's `cf-visitor` header. Reading it means reading the escaped form unless it is parsed
 * back out here.
 */
function asNestedJson(value: string): string | null {
  const trimmed = value.trim()
  if (trimmed.length < 2) return null
  const opens = trimmed.startsWith('{') && trimmed.endsWith('}')
  const isArray = trimmed.startsWith('[') && trimmed.endsWith(']')
  if (!opens && !isArray) return null

  try {
    const parsed: unknown = JSON.parse(trimmed)
    if (parsed === null || typeof parsed !== 'object') return null
    return JSON.stringify(parsed, null, 2)
  } catch {
    return null
  }
}

/** Flattens a parsed JSON record into dotted paths. */
function flatten(value: unknown, prefix: string, out: PayloadField[], depth: number): void {
  if (depth > MAX_DEPTH || out.length > 2000) return

  if (Array.isArray(value)) {
    // An empty array is a fact — "the vendor listed no rules" — and dropping the row
    // would leave the analyst unable to tell it from a field that was never sent.
    if (value.length === 0) {
      out.push({ path: prefix, value: '[]', kind: 'empty' })
      return
    }
    value.forEach((item, i) => flatten(item, `${prefix}[${i}]`, out, depth + 1))
    return
  }

  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
    if (entries.length === 0) {
      out.push({ path: prefix, value: '{}', kind: 'empty' })
      return
    }
    for (const [key, child] of entries) {
      flatten(child, prefix ? `${prefix}.${key}` : key, out, depth + 1)
    }
    return
  }

  const text = value === null || value === undefined ? '' : String(value)
  out.push(toField(prefix, text))
}

/** Reads the syslog envelope, if the line has one. */
function parseEnvelope(raw: string): PayloadField[] {
  const match = SYSLOG_PATTERN.exec(raw)
  if (!match) return []

  const [, priority, timestamp, host, tag] = match
  const pri = Number(priority)
  const facility = FACILITIES[Math.floor(pri / 8)] ?? `facility ${Math.floor(pri / 8)}`
  const severity = SEVERITIES[pri % 8] ?? `severity ${pri % 8}`

  return [
    // The number is kept beside the decode: an operator matching a syslog selector needs
    // the digits, and an analyst reading the record needs the words.
    { path: 'priority', value: `${facility}.${severity} (${pri})`, kind: 'text' },
    { path: 'timestamp', value: timestamp ?? '', kind: 'text' },
    { path: 'host', value: host ?? '', kind: 'text' },
    { path: 'tag', value: tag ?? '', kind: 'text' },
  ]
}

/** Parses `key="value"` pairs, the form every appliance-style syslog record takes. */
function parsePairs(raw: string): PayloadField[] {
  const fields: PayloadField[] = []
  const seen = new Map<string, number>()

  // Reset explicitly: PAIR_PATTERN is module-level and /g regexes carry lastIndex between
  // calls, which would make the second payload parsed start mid-record.
  PAIR_PATTERN.lastIndex = 0
  let match = PAIR_PATTERN.exec(raw)
  while (match !== null) {
    const [, key = '', value = ''] = match
    // A repeated key is suffixed rather than overwritten. F5 sends
    // management_ip_address twice by design, and last-one-wins would hide the first.
    const count = seen.get(key) ?? 0
    seen.set(key, count + 1)
    fields.push(toField(count === 0 ? key : `${key} (${count + 1})`, value))
    match = PAIR_PATTERN.exec(raw)
  }
  return fields
}

/**
 * Structures a payload for display.
 *
 * Falls back rather than fails: a record that is neither JSON nor key/value comes back as
 * `text` with `raw` intact, because a payload the console refuses to show is worse than an
 * ugly one.
 */
export function structurePayload(raw: string | null | undefined): StructuredPayload {
  const text = raw ?? ''
  const bare: StructuredPayload = {
    shape: 'text',
    fields: [],
    envelope: [],
    raw: text,
    emptyCount: 0,
  }
  if (!text.trim() || text.length > MAX_PARSE_CHARS) return bare

  const json = parseJsonRecord(text)
  if (json) return { ...bare, ...json, shape: 'json' }

  const envelope = parseEnvelope(text)
  const fields = parsePairs(text)
  // One stray `key="value"` inside a prose log line is not a structured record, and
  // presenting it as a one-row table would hide the line it came from.
  if (fields.length < 3) return bare

  return {
    ...bare,
    shape: 'fields',
    envelope,
    fields,
    emptyCount: fields.filter((f) => f.kind === 'empty').length,
  }
}

/** Flattens a whole-payload JSON record, or returns null when it is not one. */
function parseJsonRecord(text: string): Partial<StructuredPayload> | null {
  try {
    const parsed: unknown = JSON.parse(text)
    // A bare string or number is valid JSON but has no fields to show; the raw view is
    // already the best rendering of it.
    if (parsed === null || typeof parsed !== 'object') return null

    const fields: PayloadField[] = []
    flatten(parsed, '', fields, 0)
    if (fields.length === 0) return null

    return { fields, emptyCount: fields.filter((f) => f.kind === 'empty').length }
  } catch {
    return null
  }
}
