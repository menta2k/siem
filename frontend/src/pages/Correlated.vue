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
import { useRouter } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'
import { debounce } from '@/lib/debounce'
import type { components } from '@/api/schema'
import ConfidenceChip from '@/components/ConfidenceChip.vue'

type CorrelatedRequest = components['schemas']['CorrelatedRequest']

const router = useRouter()

const records = ref<CorrelatedRequest[]>([])
const loading = ref(false)
const errorMessage = ref('')

const rangeHours = ref(1)
const onlyMultiVendor = ref(true)
const onlyDisagreements = ref(false)
const host = ref('')
const clientIP = ref('')

const rangeOptions = [
  { title: 'Last 15 minutes', value: 0.25 },
  { title: 'Last hour', value: 1 },
  { title: 'Last 6 hours', value: 6 },
  { title: 'Last 24 hours', value: 24 },
]

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const to = new Date()
    const from = new Date(to.getTime() - rangeHours.value * 3_600_000)

    const { data } = await api.POST('/api/v1/search/correlated', {
      body: {
        timeRange: { from: from.toISOString(), to: to.toISOString() },
        filters: {
          // Above 1 restricts to genuine cross-vendor joins, which is the whole point
          // of the page; 1 would return every single-vendor record as well.
          ...(onlyMultiVendor.value ? { minVendorCount: 2 } : {}),
          ...(onlyDisagreements.value ? { onlyDisagreements: true } : {}),
          ...(host.value ? { requestHost: host.value } : {}),
          ...(clientIP.value ? { clientIp: clientIP.value } : {}),
        },
        page: { limit: 100 },
      },
    })
    records.value = data?.items ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
    records.value = []
  } finally {
    loading.value = false
  }
}

// The text filters used to requery only on Enter or Refresh. Typing an address and
// reading the unchanged table below it looks exactly like a filter that matched
// everything — there is nothing on screen to say the value was never applied. Debounced
// rather than immediate so a half-typed address does not query and read as "no results".
const reload = debounce(load, 400)
watch([host, clientIP], () => reload())
onUnmounted(() => reload.cancel())

onMounted(load)

const VENDOR_LABELS: Record<string, string> = {
  VENDOR_CLOUDFLARE: 'Cloudflare',
  VENDOR_F5: 'F5',
  VENDOR_DATADOME: 'DataDome',
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

const disagreementCount = computed(
  () => records.value.filter((r) => r.hasDisagreement).length,
)
</script>

<template>
  <div>
    <div class="d-flex align-center flex-wrap ga-3 mb-4">
      <h1 class="text-h5">Correlated requests</h1>
      <span class="text-body-2 text-medium-emphasis">
        One row per request, with every vendor that saw it
      </span>
      <v-spacer />
      <v-btn :loading="loading" variant="tonal" @click="load">Refresh</v-btn>
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
            @update:model-value="load"
          />
          <v-text-field
            v-model="host"
            label="Hostname"
            density="compact"
            hide-details
            clearable
            style="max-width: 240px"
            @keyup.enter="load"
          />
          <v-text-field
            v-model="clientIP"
            label="Client IP"
            density="compact"
            hide-details
            clearable
            style="max-width: 200px"
            @keyup.enter="load"
          />
          <v-switch
            v-model="onlyMultiVendor"
            label="Cross-vendor only"
            density="compact"
            hide-details
            color="primary"
            @update:model-value="load"
          />
          <v-switch
            v-model="onlyDisagreements"
            label="Disagreements only"
            density="compact"
            hide-details
            color="warning"
            @update:model-value="load"
          />
        </div>
      </v-card-text>
    </v-card>

    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4">
      {{ errorMessage }}
    </v-alert>

    <v-card>
      <v-card-title class="text-subtitle-1 d-flex align-center ga-3">
        <span>{{ records.length }} requests</span>
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
          <span class="text-caption">{{ item.firstEventTime }}</span>
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
            <v-chip
              v-if="item.hasDisagreement"
              color="warning"
              size="x-small"
              variant="flat"
            >
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
              No cross-vendor correlations in this window. That means no single request
              was reported by two vendors — usually because only one feed is delivering,
              or because the vendors disagree on the hostname or client IP that the join
              is made on.
            </template>
            <template v-else>No correlated requests in this window.</template>
          </div>
        </template>
      </v-data-table>
    </v-card>
  </div>
</template>
