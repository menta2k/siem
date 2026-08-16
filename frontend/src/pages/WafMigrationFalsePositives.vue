<script setup lang="ts">
/**
 * Stage 3: Cloudflare rules firing on traffic F5 is happy with.
 *
 * The mirror of step 2, and the reason log mode exists. A rule that matches requests F5
 * lets straight through is, most likely, matching legitimate traffic — and enforcing it
 * would break something no one was protecting against. Finding these BEFORE the rule is
 * turned up is the whole safety margin of this migration.
 *
 * "Most likely" is doing real work in that sentence. F5 not blocking something is not
 * proof it is harmless: F5 may simply have no signature for it, which is the same
 * evidence step 1 reads in the other direction. So this page ranks candidates and shows
 * the requests; it does not declare a rule wrong.
 */
import { onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import { useMigrationRange } from '@/composables/useMigrationRange'
import MigrationStageHeader from '@/components/MigrationStageHeader.vue'
import RuleAgreementTable from '@/components/RuleAgreementTable.vue'

type RuleAgreement = components['schemas']['WafRuleAgreement']

const { rangeHours, host, currentRange, queryParams } = useMigrationRange()

const rules = ref<RuleAgreement[]>([])
const loading = ref(false)
const errorMessage = ref('')
const range = ref(currentRange())

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  range.value = currentRange()

  try {
    const { data } = await api.GET('/api/v1/waf-migration/false-positives', {
      params: { query: queryParams() },
    })
    rules.value = data?.rules ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <MigrationStageHeader
      :step="3"
      title="Logging at Cloudflare, allowed by F5"
      definition="A Cloudflare rule matched in log mode and F5 let the same requests through. The rule is firing on traffic the other WAF considers legitimate."
      action="Read the requests and narrow the rule before enforcing it. Enforcing as-is would start blocking this traffic."
      :range-hours="rangeHours"
      :host="host"
      :loading="loading"
      @update:range-hours="rangeHours = $event"
      @update:host="host = $event"
      @reload="load"
    />

    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <v-card>
      <v-card-text>
        <div v-if="loading" class="d-flex align-center ga-3 py-4">
          <v-progress-circular indeterminate size="20" />
          <span class="text-body-2 text-medium-emphasis">Reading correlated records…</span>
        </div>

        <!-- An empty result here is genuinely good news, unlike an empty table, and it
             should not be mistaken for a page that failed to load. -->
        <div v-else-if="rules.length === 0" class="py-6 text-center">
          <v-icon icon="mdi-shield-check" size="32" class="text-success mb-2" />
          <div class="text-body-1">No rule is firing on traffic F5 allows.</div>
          <div class="text-body-2 text-medium-emphasis">
            Every Cloudflare rule in log mode is matching requests F5 also acted on.
          </div>
        </div>

        <template v-else>
          <div class="text-caption text-medium-emphasis mb-2">
            {{ rules.length }} rule{{ rules.length === 1 ? '' : 's' }} to read before enforcing. F5
            allowing a request is evidence, not proof — it may have no signature for this either,
            which is what step 1 measures.
          </div>
          <RuleAgreementTable :rules="rules" :range="range" sample-verdict="allowed" />
        </template>
      </v-card-text>
    </v-card>
  </div>
</template>
