<script setup lang="ts">
/**
 * Tests a candidate Cloudflare rule against the requests a stage-1 row is made of.
 *
 * Stage 1 says "F5 blocked these and Cloudflare saw nothing — write a rule". The rule then
 * had to be deployed in log mode and waited on to find out whether it works, and a mistake
 * cost a day: one rule differed from a working one by a single backslash and matched
 * nothing while looking correct.
 *
 * This asks Cloudflare's own expression engine, against the requests as captured, before
 * anything is deployed. It answers ONLY "would this catch these" — whether the rule is a
 * good idea is still the reader's call, and nothing here nudges it.
 */
import { computed, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import type { MigrationRange } from '@/composables/useMigrationRange'

type ExpressionResult = components['schemas']['WafExpressionResult']

const props = defineProps<{
  range: MigrationRange
  /** The group being tested, keyed exactly as the samples endpoint keys it. */
  violation?: string
  ruleId?: string
  requestHost?: string
  requestMethod?: string
  f5Verdict?: string
  cloudflareVerdict?: string
}>()

const expression = ref('')
const result = ref<ExpressionResult | null>(null)
const errorMessage = ref('')
const testing = ref(false)

async function test(): Promise<void> {
  if (!expression.value.trim()) return
  testing.value = true
  errorMessage.value = ''
  result.value = null

  try {
    const { data } = await api.POST('/api/v1/waf-migration/evaluate', {
      body: {
        timeRange: { from: props.range.from, to: props.range.to },
        violation: props.violation ?? '',
        ruleId: props.ruleId ?? '',
        requestHost: props.requestHost ?? '',
        requestMethod: props.requestMethod ?? '',
        f5Verdict: props.f5Verdict ?? '',
        cloudflareVerdict: props.cloudflareVerdict ?? '',
        expression: expression.value.trim(),
      },
    })
    result.value = data ?? null
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    testing.value = false
  }
}

const tested = computed(() => Number(result.value?.tested ?? 0))
const matched = computed(() => Number(result.value?.matched ?? 0))
const uncertain = computed(() => Number(result.value?.uncertain ?? 0))

/**
 * How the result reads at a glance.
 *
 * Three states, not two. "Matches everything" and "matches nothing" are both answers; a
 * rule that catches SOME of a group is the interesting one, because it usually means the
 * group holds more than one kind of request.
 */
const verdict = computed(() => {
  if (!result.value?.valid || tested.value === 0) return null
  if (matched.value === tested.value)
    return { colour: 'success', text: 'catches every request here' }
  if (matched.value === 0) return { colour: 'error', text: 'catches none of them' }
  return { colour: 'warning', text: 'catches some of them' }
})
</script>

<template>
  <div class="pa-2">
    <div class="text-caption text-medium-emphasis mb-1">
      Test a Cloudflare rule against these requests before deploying it. Evaluated by Cloudflare's
      own engine, so a match here is a match at the edge.
    </div>

    <v-textarea
      v-model="expression"
      density="compact"
      variant="outlined"
      rows="3"
      auto-grow
      hide-details
      spellcheck="false"
      class="expression mb-2"
      placeholder='(http.request.uri.path eq "/js_file.php" and http.request.method eq "POST") and (http.request.body.raw matches "(?i)filename=\"[^\"]*\.html?\"")'
      @keydown.ctrl.enter="test"
    />

    <div class="d-flex align-center ga-2 mb-2">
      <v-btn
        size="small"
        variant="tonal"
        :loading="testing"
        :disabled="!expression.trim()"
        prepend-icon="mdi-play"
        @click="test"
      >
        Test
      </v-btn>
      <span class="text-caption text-medium-emphasis">Ctrl+Enter</span>
    </div>

    <v-alert v-if="errorMessage" type="error" variant="tonal" density="compact" class="mb-2">
      {{ errorMessage }}
    </v-alert>

    <template v-if="result">
      <!-- A refused expression is an ANSWER, and it carries no counts: "0 of 20" beside the
           reason would read as a result when the question was never asked. -->
      <v-alert v-if="!result.valid" type="warning" variant="tonal" density="compact">
        <div>{{ result.error }}</div>
        <div v-if="result.unavailableFields?.length" class="text-caption mt-1">
          Cloudflare computes
          <code v-for="field in result.unavailableFields" :key="field" class="mr-1">{{
            field
          }}</code>
          at the edge, so it is not in a stored request and cannot be tested here.
        </div>
      </v-alert>

      <!-- No requests is not a failed test: the group's evidence has aged out, or the range
           holds none. Saying "0 matched" would claim the rule was judged. -->
      <div v-else-if="tested === 0" class="text-body-2 text-medium-emphasis">
        No requests are retained for this group in the selected range, so the rule has not been
        tested against anything.
      </div>

      <template v-else>
        <div class="d-flex align-center ga-2 mb-2">
          <v-chip :color="verdict?.colour" size="small" variant="tonal">
            {{ matched }} of {{ tested }} — {{ verdict?.text }}
          </v-chip>
          <!-- Reported apart from the totals so a count is never read as more certain than
               it is. -->
          <span v-if="uncertain" class="text-caption text-medium-emphasis">
            {{ uncertain }}
            {{ uncertain === 1 ? 'miss is' : 'misses are' }} uncertain — only part of the body was
            captured
          </span>
        </div>

        <v-table density="compact" class="outcomes">
          <tbody>
            <tr v-for="outcome in result.outcomes" :key="outcome.eventId">
              <td class="text-no-wrap">
                <v-icon
                  :icon="outcome.matched ? 'mdi-check' : 'mdi-close'"
                  :class="outcome.matched ? 'text-success' : 'text-medium-emphasis'"
                  size="small"
                />
              </td>
              <td>
                <!-- Interpolated, never v-html: this is attacker-controlled text. -->
                <code>{{ outcome.requestPath }}</code>
                <span v-if="outcome.requestQuery" class="text-caption text-medium-emphasis">
                  ?{{ outcome.requestQuery }}
                </span>
                <div v-if="outcome.caveat" class="text-caption text-warning">
                  {{ outcome.caveat }}
                </div>
              </td>
            </tr>
          </tbody>
        </v-table>
      </template>
    </template>
  </div>
</template>

<style scoped>
.expression :deep(textarea) {
  font-family: monospace;
  font-size: 0.78rem;
}

.outcomes code {
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}

.outcomes {
  max-height: 16rem;
  overflow: auto;
}
</style>
