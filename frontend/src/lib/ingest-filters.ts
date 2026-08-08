import type { components } from '@/api/schema'

export type IngestFilterRule = components['schemas']['IngestFilterRule']

export const FILTER_FIELDS = [
  { value: 'request_host', title: 'Hostname' },
  { value: 'request_path', title: 'URL path' },
] as const

export const FILTER_OPERATORS = [
  { value: 'equals', title: 'is exactly' },
  { value: 'suffix', title: 'ends with' },
  { value: 'prefix', title: 'starts with' },
  { value: 'contains', title: 'contains' },
] as const

/** Mirrors the server bound, so the UI refuses before the API has to. */
export const MAX_RULES = 64

const FIELD_LABELS: Record<string, string> = {
  request_host: 'hostname',
  request_path: 'URL path',
}

const OPERATOR_LABELS: Record<string, string> = {
  equals: 'is exactly',
  suffix: 'ends with',
  prefix: 'starts with',
  contains: 'contains',
}

/**
 * Renders a rule as the sentence an operator should check before saving.
 *
 * This exists because the failure mode of this feature is silent: a matched event is
 * stored NOWHERE, so a rule that is subtly wider than intended deletes traffic with no
 * copy to recover from and nothing on screen to say it happened. Reading back what the
 * rule actually means — rather than trusting that three dropdowns were set correctly — is
 * the only check available before the data is gone.
 */
export function describeRule(rule: IngestFilterRule): string {
  const values = (rule.values ?? []).filter((v) => v.trim() !== '')
  if (!rule.field || !rule.op || values.length === 0) {
    return 'Incomplete rule — it will not be saved.'
  }

  const field = FIELD_LABELS[rule.field] ?? rule.field
  const operator = OPERATOR_LABELS[rule.op] ?? rule.op
  const list =
    values.length === 1
      ? `"${values[0]}"`
      : `${values.slice(0, -1).map((v) => `"${v}"`).join(', ')} or "${values[values.length - 1]}"`

  return `Drop events where the ${field} ${operator} ${list}.`
}

/** A rule the server would accept: both selectors set and at least one real value. */
export function isComplete(rule: IngestFilterRule): boolean {
  return Boolean(rule.field) && Boolean(rule.op) && (rule.values ?? []).some((v) => v.trim() !== '')
}

/**
 * Drops incomplete rules and trims values, so a half-finished row left on screen is not
 * sent to the server to be rejected as a whole-form validation error.
 */
export function cleanRules(rules: IngestFilterRule[]): IngestFilterRule[] {
  return rules.filter(isComplete).map((rule) => ({
    field: rule.field,
    op: rule.op,
    values: (rule.values ?? []).map((v) => v.trim()).filter((v) => v !== ''),
  }))
}

/**
 * Flags rules broad enough to drop most or all of a feed.
 *
 * A prefix of "/" matches every path, and an empty-ish contains matches everything that
 * has the field at all. These are legal and occasionally intended, but far more often a
 * mistake, and the consequence is unrecoverable — so they are called out before saving
 * rather than diagnosed afterwards from a volume graph.
 */
export function overlyBroad(rule: IngestFilterRule): boolean {
  if (!isComplete(rule)) return false

  return (rule.values ?? []).some((raw) => {
    const value = raw.trim()
    if (value === '') return false
    if (rule.op === 'prefix' && rule.field === 'request_path') return value === '/'
    if (rule.op === 'contains') return value === '/' || value === '.'
    return false
  })
}
