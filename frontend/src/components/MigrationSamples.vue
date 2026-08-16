<script setup lang="ts">
/**
 * The requests behind one row, with BOTH vendors' verdicts on each.
 *
 * The counts say a group is worth acting on. Only the requests say what to write: whether
 * "Attack signature detected on POST /js_file.php" is a WordPress probe worth a rule of
 * its own, or a broken client that a rule would break further. Every stage drills into
 * this same list, because the evidence for all three questions is the same correlated
 * record read from a different side.
 */
import { computed, ref, watch } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import { usePreferencesStore } from '@/stores/preferences'
import type { MigrationRange } from '@/composables/useMigrationRange'

type Sample = components['schemas']['WafMigrationSample']

const props = defineProps<{
  range: MigrationRange
  /** Stage 1 keys on the F5 violation; stages 2 and 3 key on the Cloudflare rule. */
  violation?: string
  ruleId?: string
  requestHost?: string
  requestMethod?: string
  /** blocked | monitored | allowed — what F5 did with the requests being shown. */
  f5Verdict?: string
  /**
   * What Cloudflare did — allowed on stage 1, monitored on stages 2 and 3.
   *
   * Sent because a row's counts are computed for ONE pair of verdicts. Without it this
   * list showed requests Cloudflare had acted on beneath a group that had not counted
   * them, which is evidence contradicting the number above it.
   */
  cloudflareVerdict?: string
}>()

const prefs = usePreferencesStore()

const samples = ref<Sample[]>([])
const loading = ref(false)
const errorMessage = ref('')

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const { data } = await api.GET('/api/v1/waf-migration/samples', {
      params: {
        query: {
          'timeRange.from': props.range.from,
          'timeRange.to': props.range.to,
          limit: 20,
          violation: props.violation ?? '',
          ruleId: props.ruleId ?? '',
          requestHost: props.requestHost ?? '',
          requestMethod: props.requestMethod ?? '',
          f5Verdict: props.f5Verdict ?? '',
          cloudflareVerdict: props.cloudflareVerdict ?? '',
        },
      },
    })
    samples.value = data?.samples ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

// Immediate: the component is mounted by the row expanding, so there is no state in
// which it should sit empty waiting for something else to trigger it.
watch(
  () => [
    props.violation,
    props.ruleId,
    props.requestHost,
    props.f5Verdict,
    props.cloudflareVerdict,
  ],
  load,
  { immediate: true },
)

/** Verdict colours, matching the rest of the console so a block reads the same anywhere. */
function verdictColour(verdict?: string): string {
  switch (verdict) {
    case 'blocked':
      return 'error'
    case 'challenged':
      return 'warning'
    case 'monitored':
      return 'info'
    case 'allowed':
      return 'success'
    default:
      return 'default'
  }
}

const empty = computed(() => !loading.value && !errorMessage.value && samples.value.length === 0)
</script>

<template>
  <div class="pa-2">
    <v-alert v-if="errorMessage" type="error" variant="tonal" density="compact" class="mb-2">
      {{ errorMessage }}
    </v-alert>

    <div v-if="loading" class="d-flex align-center ga-2 py-2">
      <v-progress-circular indeterminate size="18" />
      <span class="text-caption text-medium-emphasis">Loading the requests…</span>
    </div>

    <!-- Said plainly. An empty table here reads as a broken panel, when it usually means
         the requests have aged past retention while the counts came from a rollup. -->
    <div v-else-if="empty" class="text-caption text-medium-emphasis py-2">
      No individual requests are retained for this group in the selected range.
    </div>

    <v-table v-else density="compact" class="samples">
      <thead>
        <tr>
          <th>Time</th>
          <th>Request</th>
          <th>Client</th>
          <th>F5</th>
          <th>Cloudflare</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in samples" :key="s.f5EventId">
          <td class="text-no-wrap text-caption">{{ prefs.dateTime(s.eventTime) }}</td>

          <td class="request-cell">
            <div>
              <span class="text-medium-emphasis">{{ s.requestMethod }}</span>
              <!-- Interpolated, never v-html: this is attacker-controlled text and the
                   path is exactly where a payload arrives. -->
              <code class="ml-1">{{ s.requestPath }}</code>
            </div>
            <div v-if="s.requestQuery" class="text-caption text-medium-emphasis">
              <!-- Usually the deciding field: an injection lives in the query string, and
                   ?id=1+OR+1=1 reads very differently from ?sort=price. -->
              ?{{ s.requestQuery }}
            </div>
            <div class="text-caption text-medium-emphasis">{{ s.requestHost }}</div>
          </td>

          <td class="text-caption">
            <div>{{ s.clientIp || '—' }}</div>
            <div class="text-medium-emphasis">
              {{ s.country }}<span v-if="s.clientAsn"> · AS{{ s.clientAsn }}</span>
            </div>
          </td>

          <td>
            <v-chip :color="verdictColour(s.f5Verdict)" size="x-small" variant="tonal">
              {{ s.f5Verdict }}
            </v-chip>
            <!-- Every violation, not only the grouped one: a request that tripped four is
                 a different case from one that tripped this one alone. -->
            <div class="mt-1">
              <div v-for="v in s.f5Violations" :key="v" class="text-caption text-medium-emphasis">
                {{ v }}
              </div>
            </div>
          </td>

          <td>
            <v-chip :color="verdictColour(s.cloudflareVerdict)" size="x-small" variant="tonal">
              {{ s.cloudflareVerdict }}
            </v-chip>
            <div v-if="s.attackScore" class="text-caption text-medium-emphasis mt-1">
              <!-- The scale runs BACKWARDS from every other score in the console: 1 is
                   certainly an attack, 100 certainly clean. The word travels with it. -->
              score {{ s.attackScore }}/100
              {{ s.attackScore <= 20 ? '(attack)' : s.attackScore > 50 ? '(clean)' : '' }}
            </div>
          </td>

          <td class="text-no-wrap">
            <!-- Straight to the full record: the F5 payload carries the request that
                 caused the block, which is what a new rule has to match on. -->
            <v-btn
              v-if="s.correlationId"
              size="x-small"
              variant="text"
              :to="{ name: 'correlated', params: { id: s.correlationId } }"
            >
              Both vendors
            </v-btn>
          </td>
        </tr>
      </tbody>
    </v-table>
  </div>
</template>

<style scoped>
.samples code {
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}

.request-cell {
  max-width: 28rem;
}
</style>
