import { ref } from 'vue'

/**
 * The controls every migration stage carries: how far back to look, and which site.
 *
 * Shared because the three stages are ONE piece of work read in sequence. An analyst
 * moves from "what is Cloudflare blind to" to "which rule is ready" while thinking about
 * the same host over the same days, and a range that silently reset between stages would
 * make two screens of the same migration disagree.
 */
export interface MigrationRange {
  from: string
  to: string
}

/**
 * Ranges are wider here than on the tuning page, deliberately.
 *
 * A migration decision is made on accumulated agreement, not on the last hour: this
 * deployment sees roughly fifty F5 blocks a day, so an hour of evidence is a handful of
 * requests and cannot support turning a rule on. The default is a week for that reason.
 */
export const MIGRATION_RANGES = [
  { title: 'Last 24 hours', value: 24 },
  { title: 'Last 3 days', value: 72 },
  { title: 'Last 7 days', value: 168 },
  { title: 'Last 30 days', value: 720 },
] as const

export const DEFAULT_MIGRATION_HOURS = 168

export function useMigrationRange() {
  const rangeHours = ref<number>(DEFAULT_MIGRATION_HOURS)
  const host = ref('')

  /** The range as the API takes it, computed at call time rather than held. */
  function currentRange(): MigrationRange {
    const to = new Date()
    const from = new Date(to.getTime() - rangeHours.value * 3_600_000)
    return { from: from.toISOString(), to: to.toISOString() }
  }

  /**
   * The query every stage sends.
   *
   * The host goes to the SERVER, not to a filter over the response: rows come back
   * ordered by volume, and a quiet host would be crowded out of the limit by a busy one
   * before the client ever saw it.
   */
  function queryParams(limit = 50): Record<string, string | number> {
    const { from, to } = currentRange()
    const params: Record<string, string | number> = {
      'timeRange.from': from,
      'timeRange.to': to,
      limit,
    }
    if (host.value.trim()) params.requestHost = host.value.trim()
    return params
  }

  return { rangeHours, host, currentRange, queryParams }
}
