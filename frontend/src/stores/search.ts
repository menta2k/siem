import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'

type EventSummary = components['schemas']['EventSummary']
type EventFilters = components['schemas']['EventFilters']
type Vendor = NonNullable<EventSummary['vendor']>
type Verdict = NonNullable<EventSummary['verdict']>

/** Presets for the range control, so the common cases need no date picker. */
export const RANGE_PRESETS = [
  { label: 'Last 15 minutes', minutes: 15 },
  { label: 'Last hour', minutes: 60 },
  { label: 'Last 6 hours', minutes: 360 },
  { label: 'Last 24 hours', minutes: 1440 },
  { label: 'Last 7 days', minutes: 10080 },
] as const

/** The default window. Never unset — an unbounded query is not expressible here. */
const DEFAULT_RANGE_MINUTES = 60

export interface SearchState {
  from: string
  to: string
  filters: EventFilters
}

/**
 * Search state, synchronised with the URL.
 *
 * The URL is the source of truth for a search so an investigation is shareable by
 * link. An analyst who finds something and pastes the address to a colleague must send
 * them the same result, not the same empty form — which is what happens when query
 * state lives only in component memory.
 */
export const useSearchStore = defineStore('search', () => {
  const from = ref<string>(presetFrom(DEFAULT_RANGE_MINUTES))
  const to = ref<string>(new Date().toISOString())
  const filters = ref<EventFilters>({})

  const items = ref<EventSummary[]>([])
  const cursor = ref<string>('')
  const nextCursor = ref<string>('')
  const total = ref<number>(0)
  const totalIsEstimate = ref<boolean>(false)
  const loading = ref(false)
  const errorMessage = ref('')

  const hasMore = computed(() => nextCursor.value !== '')

  /** True when any filter beyond the mandatory range is set. */
  const hasFilters = computed(() =>
    Object.values(filters.value).some(
      (v) => v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0),
    ),
  )

  function setRangePreset(minutes: number): void {
    from.value = presetFrom(minutes)
    to.value = new Date().toISOString()
  }

  function setFilters(next: EventFilters): void {
    // Replaced rather than merged: a filter the user cleared must actually clear, and
    // merging would leave it applied while the panel shows it empty.
    filters.value = { ...next }
  }

  function reset(): void {
    filters.value = {}
    setRangePreset(DEFAULT_RANGE_MINUTES)
    items.value = []
    cursor.value = ''
    nextCursor.value = ''
  }

  /** Runs the search from the first page. */
  async function search(): Promise<void> {
    cursor.value = ''
    items.value = []
    await fetchPage()
  }

  /** Appends the next page, leaving what is already shown in place. */
  async function loadMore(): Promise<void> {
    if (!hasMore.value) return
    cursor.value = nextCursor.value
    await fetchPage()
  }

  async function fetchPage(): Promise<void> {
    loading.value = true
    errorMessage.value = ''
    try {
      const { data } = await api.POST('/api/v1/search/events', {
        body: {
          timeRange: { from: from.value, to: to.value },
          filters: cleanFilters(filters.value),
          page: cursor.value ? { cursor: cursor.value } : {},
        },
      })
      items.value = [...items.value, ...(data?.items ?? [])]
      nextCursor.value = data?.page?.nextCursor ?? ''
      total.value = Number(data?.page?.total ?? 0)
      totalIsEstimate.value = data?.page?.totalIsEstimate ?? false
    } catch (err) {
      errorMessage.value = toDisplayMessage(err)
    } finally {
      loading.value = false
    }
  }

  /** Serialises the current search into URL query parameters. */
  function toQuery(): LocationQueryRaw {
    const query: LocationQueryRaw = { from: from.value, to: to.value }
    for (const [key, value] of Object.entries(cleanFilters(filters.value))) {
      query[key] = Array.isArray(value) ? value.join(',') : String(value)
    }
    return query
  }

  /**
   * Restores a search from URL query parameters.
   *
   * Unknown keys are ignored rather than rejected. A link may outlive a filter that
   * was removed, and dropping the whole search because one parameter is no longer
   * recognised is worse than running it without that filter.
   */
  function fromQuery(query: LocationQuery): void {
    const readString = (key: string): string | undefined => {
      const value = query[key]
      return typeof value === 'string' && value !== '' ? value : undefined
    }

    from.value = readString('from') ?? presetFrom(DEFAULT_RANGE_MINUTES)
    to.value = readString('to') ?? new Date().toISOString()

    const restored: EventFilters = {}
    for (const key of ['clientIp', 'requestHost', 'requestPath', 'ruleId', 'country',
      'userAgent', 'q', 'vendorRequestId', 'requestMethod'] as const) {
      const value = readString(key)
      if (value) restored[key] = value
    }
    const vendors = readString('vendor')
    if (vendors) restored.vendor = vendors.split(',') as Vendor[]
    const verdicts = readString('verdict')
    if (verdicts) restored.verdict = verdicts.split(',') as Verdict[]

    const asn = readString('asn')
    if (asn && Number.isFinite(Number(asn))) restored.asn = Number(asn)
    const minScore = readString('minScore')
    if (minScore && Number.isFinite(Number(minScore))) restored.minScore = Number(minScore)
    const maxScore = readString('maxScore')
    if (maxScore && Number.isFinite(Number(maxScore))) restored.maxScore = Number(maxScore)

    filters.value = restored
  }

  return {
    from,
    to,
    filters,
    items,
    nextCursor,
    total,
    totalIsEstimate,
    loading,
    errorMessage,
    hasMore,
    hasFilters,
    setRangePreset,
    setFilters,
    reset,
    search,
    loadMore,
    toQuery,
    fromQuery,
  }
})

function presetFrom(minutes: number): string {
  return new Date(Date.now() - minutes * 60_000).toISOString()
}

/**
 * Drops empty filters before they reach the API.
 *
 * An empty string is not a filter for "" — the backend would reject an empty IN list
 * and an empty equality match would silently return nothing.
 */
function cleanFilters(filters: EventFilters): EventFilters {
  const cleaned: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === '') continue
    if (Array.isArray(value) && value.length === 0) continue
    cleaned[key] = value
  }
  return cleaned as EventFilters
}
