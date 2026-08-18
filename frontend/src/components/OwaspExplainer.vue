<script setup lang="ts">
/**
 * Which OWASP rules a request matched, and what each one added to the score.
 *
 * Cloudflare's OWASP managed ruleset reports its decision as
 *
 *     949110: Inbound Anomaly Score Exceeded
 *
 * and nothing else. That names the decision and hides the reasoning: an operator looking at
 * a false positive cannot tell whether to raise the threshold, exclude a single rule, or
 * accept the block. 949110 is the Core Rule Set's own rule number — Cloudflare's managed
 * ruleset IS the CRS — so the server runs the same rules against the request as it was
 * logged and returns the contributors.
 *
 * It reports what matched. It does not recommend which rule to switch off: that decision
 * has consequences and belongs to whoever owns them.
 */
import { computed, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'

type OwaspResult = components['schemas']['WafOwaspResult']

const props = defineProps<{
  /** The F5 event whose stored payload holds the request. */
  eventId: string
  /** Both are what let the server SEEK the payload instead of scanning for the id. */
  receivedAt?: string
  sourceVendor?: string
}>()

const result = ref<OwaspResult | null>(null)
const errorMessage = ref('')
const loading = ref(false)

async function explain(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  result.value = null

  try {
    const { data } = await api.POST('/api/v1/waf-migration/owasp', {
      body: {
        eventId: props.eventId,
        receivedAt: props.receivedAt,
        sourceVendor: props.sourceVendor,
      },
    })
    result.value = data ?? null
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

explain()

const score = computed(() => Number(result.value?.blockingScore ?? 0))
const threshold = computed(() => Number(result.value?.threshold ?? 0))
const evaluated = computed(() => Number(result.value?.bodyEvaluated ?? 0))
const declared = computed(() => Number(result.value?.bodyDeclared ?? 0))

/**
 * The rules that built the score, heaviest first.
 *
 * 949110 is dropped from the list: it is the decision, which is already shown as the score,
 * and leaving it among the contributors makes it look like one of them.
 */
const contributors = computed(() =>
  [...(result.value?.matched ?? [])]
    .filter((match) => Number(match.id) !== 949110)
    .sort((a, b) => Number(b.score ?? 0) - Number(a.score ?? 0)),
)

/**
 * How much of the body the reading actually had.
 *
 * This is the difference that explains most disagreements with the edge: Cloudflare reads
 * the whole upload and F5 keeps roughly the first two kilobytes. Where the gap is wide,
 * "nothing matched" is not a clean bill of health, and the UI has to say so before the
 * reader draws the opposite conclusion.
 */
const bodyGap = computed(() => declared.value > evaluated.value)

const verdict = computed(() => {
  if (!result.value?.available) return null
  return result.value.wouldBlock
    ? { colour: 'error', text: 'over the threshold — OWASP would block' }
    : { colour: 'success', text: 'under the threshold — OWASP would not block' }
})

function integer(value: number): string {
  return value.toLocaleString()
}
</script>

<template>
  <div class="pa-2">
    <div v-if="loading" class="d-flex align-center ga-2 py-2">
      <v-progress-circular indeterminate size="18" />
      <span class="text-caption text-medium-emphasis">Running the OWASP rules…</span>
    </div>

    <v-alert v-else-if="errorMessage" type="error" variant="tonal" density="compact">
      {{ errorMessage }}
    </v-alert>

    <!-- A stated absence. An empty rule list and an unanswerable question look identical
         otherwise, and one of them is a clean bill of health. -->
    <v-alert v-else-if="result && !result.available" type="info" variant="tonal" density="compact">
      {{ result.error }}
    </v-alert>

    <template v-else-if="result">
      <div class="d-flex align-center flex-wrap ga-2 mb-2">
        <v-chip :color="verdict?.colour" size="small" variant="tonal">
          score {{ score }} of {{ threshold }}
        </v-chip>
        <span class="text-caption text-medium-emphasis">{{ verdict?.text }}</span>
        <v-spacer />
        <span class="text-caption text-medium-emphasis">
          paranoia level {{ result.paranoiaLevel }}
        </span>
      </div>

      <!-- Loud where it matters. On this deployment every OWASP hit is an upload, and the
           bytes that decided it are usually the ones F5 did not keep. -->
      <v-alert v-if="bodyGap" type="warning" variant="tonal" density="compact" class="mb-2">
        Only {{ integer(evaluated) }} of the {{ integer(declared) }} body bytes this request
        declared were logged, so the body rules were barely evaluated. Cloudflare saw the rest — a
        rule that did not fire here has not been ruled out.
      </v-alert>

      <div v-if="contributors.length === 0" class="text-body-2 text-medium-emphasis py-2">
        No OWASP rule matched the part of the request that was captured.
      </div>

      <v-table v-else density="compact" class="owasp">
        <tbody>
          <tr v-for="match in contributors" :key="match.id">
            <td class="text-no-wrap score-cell">
              <span v-if="Number(match.score) > 0" class="font-weight-medium">
                +{{ match.score }}
              </span>
            </td>
            <td class="text-no-wrap">
              <!-- The same number Cloudflare prints, which is the point: it can be pasted
                   straight into a managed-ruleset exclusion. -->
              <code>{{ match.id }}</code>
            </td>
            <td>
              <div>
                <!-- Interpolated, never v-html: the matched data is attacker-controlled. -->
                {{ match.message }}
              </div>
              <div v-if="match.data" class="text-caption text-medium-emphasis matched-data">
                {{ match.data }}
              </div>
              <div v-if="match.artifact" class="text-caption text-warning">
                fired on how the request was captured, not on the request itself
              </div>
            </td>
            <td class="text-no-wrap">
              <v-chip v-if="match.category" size="x-small" variant="tonal">
                {{ match.category }}
              </v-chip>
            </td>
          </tr>
        </tbody>
      </v-table>

      <div v-for="note in result.notes" :key="note" class="text-caption text-medium-emphasis mt-2">
        {{ note }}
      </div>
    </template>
  </div>
</template>

<style scoped>
.owasp code {
  font-size: 0.75rem;
}

.score-cell {
  width: 3rem;
}

.matched-data {
  overflow-wrap: anywhere;
  max-width: 32rem;
}
</style>
