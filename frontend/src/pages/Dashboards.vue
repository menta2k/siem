<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import FeedHealthChip from '@/components/FeedHealthChip.vue'

type OverviewPanel = components['schemas']['OverviewPanel']
type RulesPanel = components['schemas']['RulesPanel']
type SourcesPanel = components['schemas']['SourcesPanel']
type DisagreementsPanel = components['schemas']['DisagreementsPanel']
type FeedHealthPanel = components['schemas']['FeedHealthPanel']

const RANGE_PRESETS = [
  { label: '1h', minutes: 60, interval: 'BUCKET_INTERVAL_5M' },
  { label: '6h', minutes: 360, interval: 'BUCKET_INTERVAL_5M' },
  { label: '24h', minutes: 1440, interval: 'BUCKET_INTERVAL_1H' },
  { label: '7d', minutes: 10080, interval: 'BUCKET_INTERVAL_1H' },
  { label: '30d', minutes: 43200, interval: 'BUCKET_INTERVAL_1D' },
] as const

type Preset = (typeof RANGE_PRESETS)[number]

const selected = ref<Preset>(RANGE_PRESETS[2])
const loading = ref(false)
const errorMessage = ref('')

const overview = ref<OverviewPanel | null>(null)
const rules = ref<RulesPanel | null>(null)
const sources = ref<SourcesPanel | null>(null)
const disagreements = ref<DisagreementsPanel | null>(null)
const feedHealth = ref<FeedHealthPanel | null>(null)

/**
 * ONE range for every panel.
 *
 * The range is computed once per load and passed to all five requests. Letting each
 * panel compute its own "now" would put figures from slightly different windows side
 * by side, and two numbers on one screen that disagree are worse than no numbers —
 * the analyst cannot tell which is wrong (FR-025).
 */
function currentRange(): { from: string; to: string } {
  const to = new Date()
  const from = new Date(to.getTime() - selected.value.minutes * 60_000)
  return { from: from.toISOString(), to: to.toISOString() }
}

const rangeLabel = computed(() => {
  const { from, to } = currentRange()
  return `${new Date(from).toLocaleString()} — ${new Date(to).toLocaleString()}`
})

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''

  const range = currentRange()
  const params = {
    query: {
      'timeRange.from': range.from,
      'timeRange.to': range.to,
      interval: selected.value.interval,
      limit: 10,
    },
  }

  try {
    // Requested together so every panel reflects the same instant. Loading them in
    // sequence would let a busy tenant's traffic move between the first and the last.
    const [o, r, s, d, h] = await Promise.all([
      api.GET('/api/v1/dashboards/overview', { params }),
      api.GET('/api/v1/dashboards/rules', { params }),
      api.GET('/api/v1/dashboards/sources', { params }),
      api.GET('/api/v1/dashboards/disagreements', { params }),
      api.GET('/api/v1/dashboards/feed-health', { params }),
    ])
    overview.value = o.data ?? null
    rules.value = r.data ?? null
    sources.value = s.data ?? null
    disagreements.value = d.data ?? null
    feedHealth.value = h.data ?? null
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

function selectPreset(preset: Preset): void {
  selected.value = preset
  void load()
}

onMounted(load)

const vendorLabels: Record<string, string> = {
  VENDOR_CLOUDFLARE: 'Cloudflare',
  VENDOR_F5: 'F5',
  VENDOR_DATADOME: 'DataDome',
}

const disagreementLabels: Record<string, string> = {
  DISAGREEMENT_KIND_NONE: 'Agreed',
  DISAGREEMENT_KIND_ALLOW_VS_BLOCK: 'Allow vs block',
  DISAGREEMENT_KIND_ALLOW_VS_CHALLENGE: 'Allow vs challenge',
  DISAGREEMENT_KIND_SCORE_CONFLICT: 'Score conflict',
}

/** Traffic per vendor for the whole range, from the series the server returned. */
const volumeByVendor = computed(() => {
  const totals = new Map<string, number>()
  for (const point of overview.value?.volume ?? []) {
    const label = vendorLabels[point.vendor ?? ''] ?? 'Unknown'
    totals.set(label, (totals.get(label) ?? 0) + Number(point.events ?? 0))
  }
  return [...totals.entries()].sort((a, b) => b[1] - a[1])
})

const disagreementRate = computed(() => {
  const total = Number(disagreements.value?.totalRecords ?? 0)
  if (total === 0) return null
  return Number(disagreements.value?.totalDisagreements ?? 0) / total
})

const disagreementsByKind = computed(() => {
  const totals = new Map<string, number>()
  for (const point of disagreements.value?.points ?? []) {
    const kind = point.kind ?? ''
    if (kind === 'DISAGREEMENT_KIND_NONE') continue
    const records = Number(point.records ?? 0)
    if (records === 0) continue
    totals.set(kind, (totals.get(kind) ?? 0) + records)
  }
  return [...totals.entries()].sort((a, b) => b[1] - a[1])
})

function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

/**
 * Block rate for a source, guarding the zero-event case rather than showing NaN.
 *
 * The counts arrive as strings: 64-bit integers exceed what a JS number represents
 * exactly, so the generator emits them as strings rather than silently losing
 * precision above 2^53. Coercing here is safe because a rate only needs display
 * precision, but the raw counts are rendered as the strings they arrive as.
 */
function blockRate(events?: string | number, blocked?: string | number): string {
  const total = Number(events ?? 0)
  if (total === 0) return '—'
  return percent(Number(blocked ?? 0) / total)
}
</script>

<template>
  <div>
    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <!-- One control, five panels. -->
    <v-card class="mb-4">
      <v-card-text class="d-flex flex-wrap align-center ga-2">
        <v-icon icon="mdi-clock-outline" size="small" />
        <span class="text-body-2 mr-2">{{ rangeLabel }}</span>

        <v-btn-toggle
          :model-value="selected.label"
          density="compact"
          variant="outlined"
          divided
        >
          <v-btn
            v-for="preset in RANGE_PRESETS"
            :key="preset.label"
            :value="preset.label"
            size="small"
            @click="selectPreset(preset)"
          >
            {{ preset.label }}
          </v-btn>
        </v-btn-toggle>

        <v-spacer />
        <v-btn
          variant="text"
          size="small"
          prepend-icon="mdi-refresh"
          :loading="loading"
          @click="load"
        >
          Refresh
        </v-btn>
      </v-card-text>
    </v-card>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <v-row>
      <v-col cols="12" md="3">
        <v-card>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">Events</div>
            <div class="text-h5">{{ overview?.totalEvents ?? 0 }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">Blocked</div>
            <div class="text-h5 text-error">{{ overview?.totalBlocked ?? 0 }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">Challenged</div>
            <div class="text-h5 text-warning">{{ overview?.totalChallenged ?? 0 }}</div>
          </v-card-text>
        </v-card>
      </v-col>
      <v-col cols="12" md="3">
        <v-card>
          <v-card-text>
            <div class="text-caption text-medium-emphasis">Disagreement rate</div>
            <div class="text-h5">
              {{ disagreementRate === null ? '—' : percent(disagreementRate) }}
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-row>
      <v-col cols="12" md="6">
        <v-card class="mb-4">
          <v-card-title class="text-subtitle-1">Volume by vendor</v-card-title>
          <v-card-text>
            <v-table v-if="volumeByVendor.length" density="compact">
              <tbody>
                <tr v-for="[vendor, events] in volumeByVendor" :key="vendor">
                  <td>{{ vendor }}</td>
                  <td class="text-right">{{ events }}</td>
                </tr>
              </tbody>
            </v-table>
            <div v-else class="text-body-2 text-medium-emphasis">No traffic in this range.</div>
          </v-card-text>
        </v-card>

        <v-card class="mb-4">
          <v-card-title class="text-subtitle-1">Top rules</v-card-title>
          <v-card-text>
            <v-table v-if="rules?.rules?.length" density="compact">
              <tbody>
                <tr v-for="rule in rules.rules" :key="`${rule.vendor}-${rule.ruleId}`">
                  <td>{{ vendorLabels[rule.vendor ?? ''] ?? 'Unknown' }}</td>
                  <td>{{ rule.ruleId }}</td>
                  <td class="text-right">{{ rule.events }}</td>
                </tr>
              </tbody>
            </v-table>
            <div v-else class="text-body-2 text-medium-emphasis">
              No rules triggered in this range.
            </div>
          </v-card-text>
        </v-card>
      </v-col>

      <v-col cols="12" md="6">
        <v-card class="mb-4">
          <v-card-title class="text-subtitle-1">Top sources</v-card-title>
          <v-card-text>
            <v-table v-if="sources?.sources?.length" density="compact">
              <thead>
                <tr>
                  <th>Client</th>
                  <th>Country</th>
                  <th class="text-right">Events</th>
                  <th class="text-right">Blocked</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="source in sources.sources" :key="source.clientIp">
                  <td><code>{{ source.clientIp }}</code></td>
                  <td>{{ source.country || '—' }}</td>
                  <td class="text-right">{{ source.events }}</td>
                  <td class="text-right">{{ blockRate(source.events, source.blocked) }}</td>
                </tr>
              </tbody>
            </v-table>
            <div v-else class="text-body-2 text-medium-emphasis">No sources in this range.</div>
          </v-card-text>
        </v-card>

        <v-card class="mb-4">
          <v-card-title class="text-subtitle-1">Disagreements</v-card-title>
          <v-card-text>
            <v-table v-if="disagreementsByKind.length" density="compact">
              <tbody>
                <tr v-for="[kind, count] in disagreementsByKind" :key="kind">
                  <td>{{ disagreementLabels[kind] ?? kind }}</td>
                  <td class="text-right">{{ count }}</td>
                </tr>
              </tbody>
            </v-table>
            <div v-else class="text-body-2 text-medium-emphasis">
              Vendors agreed on every correlated request in this range.
            </div>
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-card>
      <v-card-title class="text-subtitle-1">Feed health</v-card-title>
      <v-card-text>
        <div v-if="feedHealth?.feeds?.length" class="d-flex flex-wrap ga-3">
          <v-card
            v-for="feed in feedHealth.feeds"
            :key="feed.feedId"
            variant="outlined"
            class="pa-3"
          >
            <div class="text-caption text-medium-emphasis mb-1">
              <code>{{ feed.feedId }}</code>
            </div>
            <FeedHealthChip
              :health="{
                silent: feed.silent,
                credentialValid: feed.credentialValid,
                schemaDriftWarning: feed.schemaDriftWarning,
                lastEventAt: feed.lastEventAt,
              }"
              :enabled="true"
            />
          </v-card>
        </div>
        <div v-else class="text-body-2 text-medium-emphasis">No feeds configured.</div>
      </v-card-text>
    </v-card>
  </div>
</template>
