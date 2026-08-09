<script setup lang="ts">
/**
 * The log chain behind a correlated request: every contributing event, in the order the
 * vendors observed it.
 *
 * The record above this already says WHAT the vendors concluded. This says what each of
 * them actually saw and when — which is the question an analyst reaches for the moment a
 * disagreement appears. "Cloudflare allowed it and F5 blocked it" is only actionable
 * once you can see F5's rule, Cloudflare's bot score, and how far apart the two
 * observations were.
 *
 * Events are fetched individually because a correlated record stores ids, not copies.
 * That is the right storage decision — an amendment must not duplicate event data — and
 * it costs a handful of requests here, bounded by the vendor count.
 */
import { computed, ref, watch } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import { formatPayload } from '@/lib/json-format'
import type { FormattedPayload } from '@/lib/json-format'

type EventDetail = components['schemas']['EventDetail']
type Vendor = NonNullable<components['schemas']['EventSummary']['vendor']>

const props = defineProps<{
  eventIds: string[]
  /** Vendors whose verdict differs from the rest, so the chain can mark them. */
  conflicting?: Set<string>
}>()

/** One link in the chain: the event, or why it could not be shown. */
type Link = {
  eventId: string
  detail: EventDetail | null
  error: string
}

const links = ref<Link[]>([])
const loading = ref(false)
const expanded = ref<Set<string>>(new Set())

/**
 * Bounded deliberately. A correlated record normally has one event per vendor, but a
 * heuristic join on a busy hostname can gather more, and an unbounded fan-out of
 * requests from a detail page is how one click becomes a hundred.
 */
const MAX_EVENTS = 25

async function load(): Promise<void> {
  const ids = props.eventIds.slice(0, MAX_EVENTS)
  if (ids.length === 0) {
    links.value = []
    return
  }

  loading.value = true
  try {
    // Fetched concurrently, and a failure on one is kept rather than thrown: an event
    // aged out by retention must not blank the whole chain, because the events that
    // remain are still evidence.
    links.value = await Promise.all(
      ids.map(async (eventId): Promise<Link> => {
        try {
          const { data } = await api.GET('/api/v1/events/{eventId}', {
            params: { path: { eventId } },
          })
          return { eventId, detail: data ?? null, error: '' }
        } catch (err) {
          return { eventId, detail: null, error: toDisplayMessage(err) }
        }
      }),
    )
  } finally {
    loading.value = false
  }
}

watch(() => props.eventIds, load, { immediate: true, deep: true })

/** The chain in observation order, which is what makes the propagation gap readable. */
const ordered = computed(() =>
  [...links.value].sort((a, b) => {
    const at = a.detail?.summary?.eventTime ?? ''
    const bt = b.detail?.summary?.eventTime ?? ''
    return at.localeCompare(bt)
  }),
)

const firstSeen = computed(() => {
  const t = ordered.value.find((l) => l.detail?.summary?.eventTime)?.detail?.summary?.eventTime
  return t ? new Date(t).getTime() : null
})

/**
 * How far after the first observation this one landed.
 *
 * This is the number that explains a join. Vendors sit at different points in the
 * request path, so the same request reaches them at different times; the spread is what
 * the correlation window has to accommodate, and an unexpectedly large one is usually
 * clock skew rather than latency.
 */
function offsetFromFirst(link: Link): string {
  const t = link.detail?.summary?.eventTime
  if (!t || firstSeen.value === null) return ''
  const delta = new Date(t).getTime() - firstSeen.value
  if (delta === 0) return 'first'
  return delta < 1000 ? `+${delta} ms` : `+${(delta / 1000).toFixed(2)} s`
}

const VENDOR_LABELS: Record<string, string> = {
  VENDOR_CLOUDFLARE: 'Cloudflare',
  VENDOR_F5: 'F5',
  VENDOR_DATADOME: 'DataDome',
  VENDOR_NGINX: 'nginx',
}
function vendorLabel(v: Vendor | undefined): string {
  return v ? (VENDOR_LABELS[v] ?? v) : 'unknown'
}

const VERDICT_LABELS: Record<string, string> = {
  VERDICT_ALLOWED: 'allowed',
  VERDICT_BLOCKED: 'blocked',
  VERDICT_CHALLENGED: 'challenged',
  VERDICT_RATE_LIMITED: 'rate limited',
  VERDICT_LOGGED: 'logged',
}
function verdictLabel(v: string | undefined): string {
  return v ? (VERDICT_LABELS[v] ?? v) : '—'
}

function verdictColour(v: string | undefined): string {
  switch (v) {
    case 'VERDICT_BLOCKED':
      return 'error'
    case 'VERDICT_CHALLENGED':
    case 'VERDICT_RATE_LIMITED':
      return 'warning'
    case 'VERDICT_ALLOWED':
      return 'success'
    default:
      return 'default'
  }
}

function isConflicting(link: Link): boolean {
  const vendor = link.detail?.summary?.vendor
  return vendor ? (props.conflicting?.has(vendor) ?? false) : false
}

function toggle(eventId: string): void {
  // Reassigned rather than mutated so the template tracks the change.
  const next = new Set(expanded.value)
  if (next.has(eventId)) next.delete(eventId)
  else next.add(eventId)
  expanded.value = next
}

function extraEntries(link: Link): [string, string][] {
  return Object.entries(link.detail?.rawExtra ?? {})
}

/**
 * The link's payload indented for reading, the same way the event detail panel shows it.
 * Anything that does not parse as JSON comes back exactly as received.
 */
function payloadOf(link: Link): FormattedPayload {
  return formatPayload(link.detail?.rawPayload)
}
</script>

<template>
  <v-card>
    <v-card-title class="text-subtitle-1">
      Log chain
      <span class="text-caption text-medium-emphasis ml-2">
        what each vendor saw, in observation order
      </span>
    </v-card-title>

    <v-card-text>
      <div v-if="loading" class="d-flex align-center ga-3 py-4">
        <v-progress-circular indeterminate size="20" />
        <span class="text-body-2 text-medium-emphasis">Loading contributing events…</span>
      </div>

      <div v-else-if="ordered.length === 0" class="text-body-2 text-medium-emphasis py-2">
        This record lists no contributing events.
      </div>

      <v-timeline v-else side="end" density="compact" truncate-line="both">
        <v-timeline-item
          v-for="link in ordered"
          :key="link.eventId"
          :dot-color="verdictColour(link.detail?.summary?.verdict)"
          size="small"
        >
          <!-- An event the platform can no longer show. Said plainly rather than
               rendered as an empty row, which would read as "this vendor saw nothing". -->
          <div v-if="link.error" class="text-body-2">
            <code>{{ link.eventId }}</code>
            <div class="text-caption text-error">{{ link.error }}</div>
          </div>

          <div v-else>
            <div class="d-flex align-center flex-wrap ga-2">
              <span class="font-weight-medium">
                {{ vendorLabel(link.detail?.summary?.vendor) }}
              </span>
              <v-chip
                :color="verdictColour(link.detail?.summary?.verdict)"
                size="x-small"
                variant="tonal"
              >
                {{ verdictLabel(link.detail?.summary?.verdict) }}
              </v-chip>
              <!-- Marked, not merely coloured: a disagreement is the reason this record
                   is worth reading, and colour alone excludes anyone who cannot see it. -->
              <v-chip v-if="isConflicting(link)" color="warning" size="x-small" variant="flat">
                disagrees
              </v-chip>
              <span class="text-caption text-medium-emphasis">
                {{ link.detail?.summary?.eventTime }}
              </span>
              <!-- Inline, not in the timeline's `opposite` slot: Vuetify drops that slot
                   when `side` is set, so the offset silently never rendered — and the
                   gap between vendors is one of the main things this view is read for. -->
              <v-chip size="x-small" variant="text" class="px-1">
                {{ offsetFromFirst(link) }}
              </v-chip>
            </div>

            <div class="text-caption text-medium-emphasis mt-1">
              <template v-if="link.detail?.summary?.ruleId">
                rule <code>{{ link.detail?.summary?.ruleId }}</code>
              </template>
              <template v-if="link.detail?.summary?.score !== undefined">
                · score {{ link.detail?.summary?.score }}
                {{ link.detail?.summary?.scoreKind }}
              </template>
              <template v-if="link.detail?.summary?.vendorRequestId">
                · vendor id <code>{{ link.detail?.summary?.vendorRequestId }}</code>
              </template>
              <!-- Shown separately from the vendor id because they are different
                   things: the vendor id is the identifier SHARED between vendors and
                   is why these events joined, while this is F5's own reference. -->
              <template v-if="link.detail?.summary?.vendorEventId">
                · support id <code>{{ link.detail?.summary?.vendorEventId }}</code>
              </template>
            </div>

            <v-btn size="x-small" variant="text" class="px-0 mt-1" @click="toggle(link.eventId)">
              {{ expanded.has(link.eventId) ? 'Hide' : 'Show' }} what
              {{ vendorLabel(link.detail?.summary?.vendor) }} sent
            </v-btn>

            <div v-if="expanded.has(link.eventId)" class="mt-2">
              <!-- Vendor-native fields with no home in the common model. This is where a
                   vendor's own reasoning lives, and flattening it away is how a SIEM
                   loses the detail that explains the verdict. -->
              <v-table v-if="extraEntries(link).length" density="compact" class="mb-3">
                <tbody>
                  <tr v-for="[key, value] in extraEntries(link)" :key="key">
                    <td class="text-caption text-medium-emphasis">{{ key }}</td>
                    <!-- Interpolated, never v-html: this is vendor-controlled text. -->
                    <td class="text-caption">{{ value }}</td>
                  </tr>
                </tbody>
              </v-table>

              <div class="text-caption text-medium-emphasis mb-1">
                {{
                  payloadOf(link).pretty
                    ? 'Raw payload, formatted'
                    : 'Raw payload, exactly as received'
                }}
              </div>
              <pre class="raw-payload">{{ payloadOf(link).text }}</pre>
            </div>
          </div>
        </v-timeline-item>
      </v-timeline>

      <div v-if="props.eventIds.length > MAX_EVENTS" class="text-caption text-medium-emphasis mt-2">
        Showing the first {{ MAX_EVENTS }} of {{ props.eventIds.length }} contributing events.
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.raw-payload {
  font-family: monospace;
  font-size: 0.75rem;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 18rem;
  overflow: auto;
  padding: 0.5rem;
  border-radius: 4px;
  background: rgb(var(--v-theme-surface-light, var(--v-theme-surface)));
}
</style>
