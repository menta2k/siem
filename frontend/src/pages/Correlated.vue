<script setup lang="ts">
/**
 * Correlated requests: one row per request, with every vendor that saw it.
 *
 * This is the product's centre of gravity and it had no page. The API has always
 * supported the query; the console could only reach a correlated record by drilling
 * from a single event in Search, which requires already knowing which event to open —
 * the opposite of how an analyst works. The question is "which requests did the vendors
 * see differently", and that has to be browsable.
 *
 * Defaults to cross-vendor joins only. A single-vendor record is a perfectly normal
 * outcome — plenty of hostnames sit behind one vendor — but it is not what anyone opens
 * this page to find.
 */
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'
import { debounce } from '@/lib/debounce'
import type { components } from '@/api/schema'
import ConfidenceChip from '@/components/ConfidenceChip.vue'
import { usePreferencesStore } from '@/stores/preferences'

const prefs = usePreferencesStore()

type CorrelatedRequest = components['schemas']['CorrelatedRequest']

const router = useRouter()
const route = useRoute()

const records = ref<CorrelatedRequest[]>([])
const loading = ref(false)
const errorMessage = ref('')

// Cursor pagination. The first page was the only page: the API has always returned a
// next_cursor and a total, and the page discarded both — so anything past the first
// hundred rows was unreachable, and a busy hour looked like a quiet one.
const nextCursor = ref('')
const total = ref(0)
const totalIsEstimate = ref(false)
const hasMore = computed(() => nextCursor.value !== '')

// The window is pinned when a search starts and reused for every following page.
// Recomputing "now" per page would slide the range under the cursor, so rows would be
// skipped or repeated as the pages advanced.
const rangeFrom = ref('')
const rangeTo = ref('')

const PAGE_SIZE = 200

// Cancels the results of a superseded request. Filters are debounced, so a slow first
// reply can land after a faster second one and append rows that no longer match.
let generation = 0

const rangeHours = ref(1)
const onlyMultiVendor = ref(true)
const onlyDisagreements = ref(false)
// "Blocked at any provider" is exactly combined_outcome == blocked: the combined
// outcome is the MOST RESTRICTIVE verdict any vendor reached, and blocked outranks
// every other verdict. Filtering the per-vendor verdict map instead would ask the
// database to scan a Map column for the same answer a LowCardinality column already
// holds.
const onlyBlocked = ref(false)
const host = ref('')
const clientIP = ref('')
// The two identifiers, resolved server-side to the events carrying them. A ray reaches
// every vendor that saw the request; a support id reaches F5's record of it.
const ray = ref('')
const supportID = ref('')

const rangeOptions = [
  { title: 'Last 15 minutes', value: 0.25 },
  { title: 'Last hour', value: 1 },
  { title: 'Last 6 hours', value: 6 },
  { title: 'Last 24 hours', value: 24 },
]

async function load(append = false): Promise<void> {
  const mine = ++generation
  loading.value = true
  errorMessage.value = ''

  if (!append) {
    const to = new Date()
    rangeTo.value = to.toISOString()
    rangeFrom.value = new Date(to.getTime() - rangeHours.value * 3_600_000).toISOString()
    nextCursor.value = ''
  }

  try {
    const { data } = await api.POST('/api/v1/search/correlated', {
      body: {
        timeRange: { from: rangeFrom.value, to: rangeTo.value },
        filters: {
          // Above 1 restricts to genuine cross-vendor joins, which is the whole point
          // of the page; 1 would return every single-vendor record as well.
          ...(onlyMultiVendor.value ? { minVendorCount: 2 } : {}),
          ...(onlyDisagreements.value ? { onlyDisagreements: true } : {}),
          ...(onlyBlocked.value ? { combinedOutcome: 'VERDICT_BLOCKED' as const } : {}),
          ...(host.value ? { requestHost: host.value } : {}),
          ...(clientIP.value ? { clientIp: clientIP.value } : {}),
          ...(ray.value ? { vendorRequestId: ray.value } : {}),
          ...(supportID.value ? { vendorEventId: supportID.value } : {}),
        },
        page:
          append && nextCursor.value
            ? { cursor: nextCursor.value, limit: PAGE_SIZE }
            : { limit: PAGE_SIZE },
      },
    })

    if (mine !== generation) return

    const items = data?.items ?? []
    records.value = append ? [...records.value, ...items] : items
    nextCursor.value = data?.page?.nextCursor ?? ''
    total.value = Number(data?.page?.total ?? 0)
    totalIsEstimate.value = data?.page?.totalIsEstimate ?? false
  } catch (err) {
    if (mine !== generation) return
    errorMessage.value = toDisplayMessage(err)
    if (!append) records.value = []
  } finally {
    if (mine === generation) loading.value = false
  }
}

function loadMore(): void {
  void load(true)
}

/**
 * Starts a fresh search from page one.
 *
 * Bound in the template instead of `load` itself: a Vue event handler passes its event
 * as the first argument, so `@click="load"` would hand a MouseEvent to `append` and a
 * v-select would hand it the newly selected value. Both are truthy, so changing the
 * time range would have APPENDED a page of the new range onto the results of the old
 * one rather than replacing them.
 */
function refresh(): void {
  void load(false)
}

// The text filters used to requery only on Enter or Refresh. Typing an address and
// reading the unchanged table below it looks exactly like a filter that matched
// everything — there is nothing on screen to say the value was never applied. Debounced
// rather than immediate so a half-typed address does not query and read as "no results".
const reload = debounce(refresh, 400)
watch([host, clientIP, ray, supportID], () => reload())
onUnmounted(() => reload.cancel())

/**
 * Seeded from the URL so a link can land on a specific request.
 *
 * Search links here with a ray rather than fetching a correlation id, because an event
 * does not carry one — the record stores event ids, and resolving the other direction
 * is the lookup this page already does.
 */
onMounted(() => {
  const q = route.query
  if (typeof q.ray === 'string') ray.value = q.ray
  if (typeof q.supportId === 'string') supportID.value = q.supportId
  if (typeof q.clientIp === 'string') clientIP.value = q.clientIp
  if (typeof q.host === 'string') host.value = q.host
  // A link to one request should not also be filtered to cross-vendor records: a
  // single-vendor result is the honest answer when only one vendor saw it.
  if (ray.value || supportID.value) onlyMultiVendor.value = false
  refresh()
})

const VENDOR_LABELS: Record<string, string> = {
  VENDOR_CLOUDFLARE: 'Cloudflare',
  VENDOR_F5: 'F5',
  VENDOR_DATADOME: 'DataDome',
  VENDOR_NGINX: 'nginx',
}

const VERDICT_LABELS: Record<string, string> = {
  VERDICT_ALLOWED: 'allowed',
  VERDICT_BLOCKED: 'blocked',
  VERDICT_CHALLENGED: 'challenged',
  VERDICT_RATE_LIMITED: 'rate limited',
  VERDICT_MONITORED: 'monitored',
  VERDICT_LOGGED: 'logged',
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
      return 'grey'
  }
}

/** Each vendor and what it concluded, which is what makes a disagreement readable. */
function vendorVerdicts(r: CorrelatedRequest) {
  return (r.vendorVerdicts ?? []).map((v) => ({
    vendor: VENDOR_LABELS[v.vendor ?? ''] ?? v.vendor ?? '?',
    verdict: VERDICT_LABELS[v.verdict ?? ''] ?? v.verdict ?? '?',
    colour: verdictColour(v.verdict),
  }))
}

function open(r: CorrelatedRequest): void {
  if (r.correlationId) {
    router.push({ name: 'correlated', params: { id: r.correlationId } })
  }
}

/** Row click. Declared here because a template expression cannot carry type annotations. */
function onRowClick(_event: unknown, row: { item: CorrelatedRequest }): void {
  open(row.item)
}

const disagreementCount = computed(() => records.value.filter((r) => r.hasDisagreement).length)
</script>

<template>
  <div>
    <div class="d-flex align-center flex-wrap ga-3 mb-4">
      <h1 class="text-h5">Correlated requests</h1>
      <span class="text-body-2 text-medium-emphasis">
        One row per request, with every vendor that saw it
      </span>
      <v-spacer />
      <v-btn :loading="loading" variant="tonal" @click="refresh">Refresh</v-btn>
    </div>

    <v-card class="mb-4">
      <v-card-text>
        <div class="d-flex align-center flex-wrap ga-4">
          <v-select
            v-model="rangeHours"
            :items="rangeOptions"
            label="Time range"
            density="compact"
            hide-details
            style="max-width: 200px"
            @update:model-value="refresh"
          />
          <v-text-field
            v-model="host"
            label="Hostname"
            density="compact"
            hide-details
            clearable
            style="max-width: 240px"
            @keyup.enter="refresh"
          />
          <v-text-field
            v-model="clientIP"
            label="Client IP"
            density="compact"
            hide-details
            clearable
            style="max-width: 200px"
            @keyup.enter="refresh"
          />
          <v-text-field
            v-model="ray"
            label="Request ID (CF-Ray)"
            density="compact"
            hide-details
            clearable
            style="max-width: 220px"
            @keyup.enter="refresh"
          />
          <v-text-field
            v-model="supportID"
            label="Support ID (F5)"
            density="compact"
            hide-details
            clearable
            style="max-width: 200px"
            @keyup.enter="refresh"
          />
          <v-switch
            v-model="onlyMultiVendor"
            label="Cross-vendor only"
            density="compact"
            hide-details
            color="primary"
            @update:model-value="refresh"
          />
          <v-switch
            v-model="onlyDisagreements"
            label="Disagreements only"
            density="compact"
            hide-details
            color="warning"
            @update:model-value="refresh"
          />
          <v-switch
            v-model="onlyBlocked"
            label="Blocked at any provider"
            density="compact"
            hide-details
            color="error"
            @update:model-value="refresh"
          />
        </div>
      </v-card-text>
    </v-card>

    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4">
      {{ errorMessage }}
    </v-alert>

    <v-card>
      <v-card-title class="text-subtitle-1 d-flex align-center ga-3">
        <span> {{ records.length }} of {{ totalIsEstimate ? '~' : '' }}{{ total }} requests </span>
        <v-chip v-if="disagreementCount" color="warning" size="small" variant="tonal">
          {{ disagreementCount }} with a disagreement
        </v-chip>
      </v-card-title>

      <v-data-table
        :items="records"
        :loading="loading"
        :headers="[
          { title: 'First seen', key: 'firstEventTime' },
          { title: 'Host', key: 'host' },
          { title: 'Path', key: 'path' },
          { title: 'Client', key: 'client' },
          { title: 'What each vendor said', key: 'vendors', sortable: false },
          { title: 'Outcome', key: 'combinedOutcome' },
          { title: 'Confidence', key: 'confidence', sortable: false },
        ]"
        items-per-page="25"
        hover
        @click:row="onRowClick"
      >
        <template #item.firstEventTime="{ item }">
          <span class="text-caption">{{ prefs.dateTime(item.firstEventTime) }}</span>
        </template>

        <!-- Interpolated, never v-html: every one of these is vendor-supplied text. -->
        <template #item.host="{ item }">{{ item.request?.host || '—' }}</template>
        <template #item.path="{ item }">
          <span class="text-truncate d-inline-block" style="max-width: 260px">
            {{ item.request?.path || '—' }}
          </span>
        </template>
        <template #item.client="{ item }">
          <span class="text-caption">{{ item.client?.ip || '—' }}</span>
        </template>

        <!-- The row's reason for existing: each vendor's own verdict, side by side. A
             single combined outcome would hide exactly the disagreement worth seeing. -->
        <template #item.vendors="{ item }">
          <div class="d-flex flex-wrap ga-1">
            <v-chip
              v-for="v in vendorVerdicts(item)"
              :key="v.vendor"
              :color="v.colour"
              size="x-small"
              variant="tonal"
            >
              {{ v.vendor }}: {{ v.verdict }}
            </v-chip>
            <v-chip v-if="item.hasDisagreement" color="warning" size="x-small" variant="flat">
              disagree
            </v-chip>
          </div>
        </template>

        <template #item.combinedOutcome="{ item }">
          <v-chip :color="verdictColour(item.combinedOutcome)" size="small" variant="tonal">
            {{ VERDICT_LABELS[item.combinedOutcome ?? ''] ?? '—' }}
          </v-chip>
        </template>

        <template #item.confidence="{ item }">
          <ConfidenceChip :confidence="item.confidence" :join-tier="item.joinTier" />
        </template>

        <template #no-data>
          <div class="pa-8 text-center text-medium-emphasis">
            <template v-if="onlyMultiVendor">
              No cross-vendor correlations in this window. That means no single request was reported
              by two vendors — usually because only one feed is delivering, or because the vendors
              disagree on the hostname or client IP that the join is made on.
            </template>
            <template v-else>No correlated requests in this window.</template>
          </div>
        </template>
      </v-data-table>

      <!-- The cursor is the only way past the first page: the result set is ordered by
           time and offset paging over a moving window would skip or repeat rows. -->
      <v-card-actions v-if="hasMore" class="justify-center py-4">
        <v-btn variant="tonal" :loading="loading" @click="loadMore">
          Load {{ PAGE_SIZE }} more
        </v-btn>
      </v-card-actions>
      <div v-else-if="records.length" class="text-center text-caption text-medium-emphasis pb-4">
        End of results.
      </div>
    </v-card>
  </div>
</template>
