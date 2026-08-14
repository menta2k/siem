<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'

type RuleProfile = components['schemas']['WafRuleProfile']
type CoverageGap = components['schemas']['WafCoverageGap']
type PathCount = components['schemas']['WafPathCount']
type Corroboration = components['schemas']['WafCorroboration']

/**
 * Evidence for tuning a Cloudflare ruleset.
 *
 * This page reports and never prescribes. Which rules to enforce and which to except is
 * a decision whose consequences land on whoever owns the site, so the job here is to put
 * the numbers behind that decision on one screen and make them hard to misread — above
 * all the attack score, whose scale runs backwards from every other score in the console.
 */
const tab = ref<'rules' | 'gaps'>('rules')
const rangeHours = ref(24)
// Both filters are sent to the server rather than applied here. Rules are ordered by
// volume, so an allowlist matching thousands always outranks a detection matching ten —
// filtering the response would return nothing for exactly the rules worth finding.
const actionFilter = ref('')
const readingFilter = ref('')
const rules = ref<RuleProfile[]>([])
const gaps = ref<CoverageGap[]>([])
const loading = ref(false)
const errorMessage = ref('')

/** Per-rule drill-down, loaded on demand: paths and cross-vendor corroboration. */
const expanded = ref<string | null>(null)
const paths = ref<PathCount[]>([])
const corroboration = ref<Corroboration | null>(null)
const detailLoading = ref(false)

const actionOptions = [
  { title: 'Any action', value: '' },
  { title: 'log — matched, not enforced', value: 'log' },
  { title: 'block', value: 'block' },
  { title: 'managedChallenge', value: 'managedChallenge' },
  { title: 'skip — bypasses the rules behind it', value: 'skip' },
]

// The vocabulary the server computes, not a second definition of it.
const readingOptions = [
  { title: 'Any reading', value: '' },
  { title: 'Scores as attacks', value: 'attacks' },
  { title: 'Scores as clean', value: 'clean' },
  { title: 'Mixed', value: 'mixed' },
  { title: 'Exempting traffic', value: 'exempting' },
  { title: 'Unscored', value: 'unscored' },
]

const rangeOptions = [
  { title: 'Last hour', value: 1 },
  { title: 'Last 6 hours', value: 6 },
  { title: 'Last 24 hours', value: 24 },
  { title: 'Last 7 days', value: 168 },
]

function currentRange() {
  const to = new Date()
  const from = new Date(to.getTime() - rangeHours.value * 3_600_000)
  return { from: from.toISOString(), to: to.toISOString() }
}

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  expanded.value = null
  const { from, to } = currentRange()
  const base = { 'timeRange.from': from, 'timeRange.to': to, limit: 50 }

  try {
    const [r, g] = await Promise.all([
      api.GET('/api/v1/waf-tuning/rules', {
        params: {
          query: { ...base, action: actionFilter.value, reading: readingFilter.value },
        },
      }),
      // The gaps view is keyed on the absence of a rule, so neither filter applies.
      api.GET('/api/v1/waf-tuning/gaps', { params: { query: base } }),
    ])
    rules.value = r.data?.rules ?? []
    gaps.value = g.data?.gaps ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

/**
 * Opens one rule's evidence: the URLs it fires on, and what the other vendors made of
 * the same requests. Loaded on demand because both are per-rule queries and fetching
 * them for every row would turn one page into fifty.
 */
async function toggle(rule: RuleProfile): Promise<void> {
  const key = rowKey(rule)
  if (expanded.value === key) {
    expanded.value = null
    return
  }

  expanded.value = key
  paths.value = []
  corroboration.value = null
  detailLoading.value = true

  const { from, to } = currentRange()
  const params = {
    path: { ruleId: rule.ruleId ?? '' },
    query: { 'timeRange.from': from, 'timeRange.to': to, limit: 20 },
  }

  try {
    const [p, c] = await Promise.all([
      api.GET('/api/v1/waf-tuning/rules/{ruleId}/paths', { params }),
      api.GET('/api/v1/waf-tuning/rules/{ruleId}/corroboration', { params }),
    ])
    paths.value = p.data?.paths ?? []
    corroboration.value = c.data ?? null
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    detailLoading.value = false
  }
}

function rowKey(r: RuleProfile): string {
  return `${r.ruleId}|${r.requestHost}|${r.action}|${r.source}`
}

function count(v: string | number | undefined): number {
  return Number(v ?? 0)
}

/**
 * Presentation for the reading the SERVER computed.
 *
 * The classification itself is deliberately not recomputed here. It decides which rows a
 * filter returns, and a second copy of the thresholds in the browser would eventually
 * disagree with the one the query used — showing a row labelled one thing that a filter
 * for that same thing does not return.
 */
function readingLabel(r: RuleProfile): string {
  switch (r.reading) {
    case 'exempting':
      return 'exempting traffic'
    case 'attacks':
      return 'scores as attacks'
    case 'clean':
      return 'scores as clean'
    case 'mixed':
      return 'mixed'
    case 'unscored':
      return 'unscored'
    default:
      return r.reading ?? ''
  }
}

function readingColor(r: RuleProfile): string {
  switch (r.reading) {
    case 'attacks':
      return 'error'
    case 'clean':
      return 'success'
    case 'mixed':
      return 'warning'
    case 'exempting':
      return 'info'
    default:
      return 'default'
  }
}

/** The numbers behind the label, so the reading is never asserted without its evidence. */
function readingDetail(r: RuleProfile): string {
  const attack = count(r.attackEvents)
  const suspicious = count(r.suspiciousEvents)
  const clean = count(r.cleanEvents)
  const total = attack + suspicious + clean

  if (r.reading === 'exempting') {
    return `${count(r.events).toLocaleString()} requests bypassed the rules behind this`
  }
  if (r.reading === 'unscored' || total === 0) {
    return 'no attack score on these requests'
  }
  if (r.reading === 'clean') {
    return `${clean} of ${total} scored above 50 — the WAF disagrees with this rule`
  }
  return `${attack + suspicious} of ${total} scored 1-50`
}

/** `log` is the state a tuning decision acts on; `skip` disables everything behind it. */
function actionColor(action: string | undefined): string {
  switch ((action ?? '').toLowerCase()) {
    case 'log':
      return 'warning'
    case 'block':
      return 'error'
    case 'skip':
      return 'info'
    default:
      return 'default'
  }
}

const hasRules = computed(() => rules.value.length > 0)
</script>

<template>
  <v-container fluid>
    <div class="d-flex align-center flex-wrap ga-3 mb-4">
      <div class="text-h6">WAF tuning</div>
      <v-select
        v-model="rangeHours"
        :items="rangeOptions"
        density="compact"
        variant="outlined"
        hide-details
        style="max-width: 180px"
        @update:model-value="load"
      />
      <v-select
        v-model="actionFilter"
        :items="actionOptions"
        label="Action"
        density="compact"
        variant="outlined"
        hide-details
        style="max-width: 260px"
        @update:model-value="load"
      />
      <v-select
        v-model="readingFilter"
        :items="readingOptions"
        label="Reading"
        density="compact"
        variant="outlined"
        hide-details
        style="max-width: 200px"
        @update:model-value="load"
      />
      <v-btn size="small" variant="text" :loading="loading" @click="load">Refresh</v-btn>
    </div>

    <v-alert v-if="errorMessage" type="error" variant="tonal" density="compact" class="mb-4">
      {{ errorMessage }}
    </v-alert>

    <!-- The scale is inverted and this is the one screen where that matters most, so it
         is stated once at the top rather than left to be inferred from the chips. -->
    <v-alert type="info" variant="tonal" density="compact" class="mb-4">
      Cloudflare's attack score runs <strong>1 to 100 with low meaning attack</strong> — 1 is
      certainly an attack, 100 certainly clean. A rule firing on high-scoring traffic is one the
      WAF's own model disagrees with.
    </v-alert>

    <v-tabs v-model="tab" class="mb-4">
      <v-tab value="rules">Rules ({{ rules.length }})</v-tab>
      <v-tab value="gaps">Coverage gaps ({{ gaps.length }})</v-tab>
    </v-tabs>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <v-window v-model="tab">
      <v-window-item value="rules">
        <v-card v-if="!hasRules && !loading">
          <v-card-text class="text-medium-emphasis">
            <template v-if="actionFilter || readingFilter">
              No rule matches these filters in this window.
            </template>
            <template v-else>
              No rule matched in this window. Managed rules in log mode only produce a record when
              traffic actually matches them, so a quiet period is normal.
            </template>
          </v-card-text>
        </v-card>

        <v-card v-else>
          <v-table density="compact">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Host</th>
                <th>Action</th>
                <th>Reading</th>
                <th class="text-right">Score split</th>
                <th class="text-right">Requests</th>
              </tr>
            </thead>
            <tbody>
              <template v-for="r in rules" :key="rowKey(r)">
                <tr style="cursor: pointer" @click="toggle(r)">
                  <td>
                    <!-- Interpolated, never v-html: rule names come from the vendor. -->
                    <div class="text-body-2">{{ r.ruleDescription || 'Unnamed rule' }}</div>
                    <code class="text-caption text-medium-emphasis">{{ r.ruleId }}</code>
                  </td>
                  <td class="text-body-2">{{ r.requestHost }}</td>
                  <td>
                    <v-chip :color="actionColor(r.action)" size="x-small" variant="tonal">
                      {{ r.action || '—' }}
                    </v-chip>
                    <div class="text-caption text-medium-emphasis">{{ r.source }}</div>
                  </td>
                  <td>
                    <v-chip :color="readingColor(r)" size="x-small" variant="tonal">
                      {{ readingLabel(r) }}
                    </v-chip>
                    <div class="text-caption text-medium-emphasis">{{ readingDetail(r) }}</div>
                  </td>
                  <td class="text-right text-caption text-no-wrap">
                    <span class="text-error">{{ count(r.attackEvents) }} attack</span> ·
                    <span class="text-warning">{{ count(r.suspiciousEvents) }} susp</span> ·
                    <span class="text-success">{{ count(r.cleanEvents) }} clean</span>
                  </td>
                  <td class="text-right">{{ count(r.events).toLocaleString() }}</td>
                </tr>

                <tr v-if="expanded === rowKey(r)" :key="`${rowKey(r)}-detail`">
                  <td colspan="6" class="pa-4">
                    <v-progress-circular v-if="detailLoading" indeterminate size="20" />

                    <template v-else>
                      <!-- The strongest evidence available, and the thing a single-vendor
                           WAF console can never show. -->
                      <div v-if="corroboration" class="mb-3">
                        <div class="text-caption font-weight-medium mb-1">
                          What the other vendors did
                        </div>
                        <div v-if="count(corroboration.correlated) === 0" class="text-body-2">
                          None of these requests were seen by another vendor, so there is no
                          independent opinion to compare against.
                        </div>
                        <div v-else class="text-body-2">
                          <span class="text-error">
                            {{ count(corroboration.confirmedByOthers) }}
                          </span>
                          blocked or challenged independently, and
                          <span class="text-success">
                            {{ count(corroboration.allowedByOthers) }}
                          </span>
                          allowed, out of {{ count(corroboration.correlated) }} requests another
                          vendor also saw.
                        </div>
                      </div>

                      <div class="text-caption font-weight-medium mb-1">Where it fires</div>
                      <v-table v-if="paths.length" density="compact">
                        <tbody>
                          <tr v-for="p in paths" :key="`${p.requestHost}${p.requestPath}`">
                            <td class="text-caption">{{ p.requestHost }}</td>
                            <td class="text-caption text-break">
                              <code>{{ p.requestPath }}</code>
                            </td>
                            <td class="text-caption text-right">
                              score {{ Math.round(Number(p.meanScore ?? 0)) }}
                            </td>
                            <td class="text-caption text-right">{{ count(p.events) }}</td>
                          </tr>
                        </tbody>
                      </v-table>
                      <div v-else class="text-body-2 text-medium-emphasis">
                        No matching requests remain in the retained window.
                      </div>
                    </template>
                  </td>
                </tr>
              </template>
            </tbody>
          </v-table>
        </v-card>
      </v-window-item>

      <v-window-item value="gaps">
        <v-card>
          <v-card-text class="text-caption text-medium-emphasis">
            Requests the WAF scored as an attack that <strong>no rule matched</strong>. The mirror
            image of a false positive: a hole in the ruleset rather than noise in it.
          </v-card-text>
          <v-table v-if="gaps.length" density="compact">
            <thead>
              <tr>
                <th>Host</th>
                <th class="text-right">Scored 1-20</th>
                <th class="text-right">Scored 21-50</th>
                <th class="text-right">Requests</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="g in gaps" :key="g.requestHost">
                <td class="text-body-2">{{ g.requestHost }}</td>
                <td class="text-right text-error">{{ count(g.attackEvents) }}</td>
                <td class="text-right text-warning">{{ count(g.suspiciousEvents) }}</td>
                <td class="text-right">{{ count(g.events).toLocaleString() }}</td>
              </tr>
            </tbody>
          </v-table>
          <v-card-text v-else class="text-medium-emphasis">
            Nothing scored as an attack went unmatched in this window.
          </v-card-text>
        </v-card>
      </v-window-item>
    </v-window>
  </v-container>
</template>
