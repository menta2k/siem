<script setup lang="ts">
/**
 * Stage 2: Cloudflare rules that agree with F5 and can be turned up to block.
 *
 * A rule sitting in log mode is doing nothing except accumulating the evidence this page
 * reads. When F5 independently blocked the same requests, the two systems are catching
 * the same thing and the Cloudflare rule can carry it — which is the point of the whole
 * move, because it stops the traffic at the edge instead of at the origin.
 *
 * Rules the vendors only half agree on are shown here too, marked. They are the cases
 * that most need a person, and leaving them off both this stage and the false-positive
 * stage would make them invisible on the only screens built to find them.
 */
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import { useMigrationRange } from '@/composables/useMigrationRange'
import MigrationStageHeader from '@/components/MigrationStageHeader.vue'
import RuleAgreementTable from '@/components/RuleAgreementTable.vue'

type RuleAgreement = components['schemas']['WafRuleAgreement']

const { rangeHours, host, currentRange, queryParams } = useMigrationRange()

const rules = ref<RuleAgreement[]>([])
/** The floor the server applies before it will judge a rule. */
const minCorrelated = ref(0)
const loading = ref(false)
const errorMessage = ref('')
const range = ref(currentRange())

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  // Frozen for the page, so a row's samples come from the window its counts did.
  range.value = currentRange()

  try {
    const { data } = await api.GET('/api/v1/waf-migration/ready', {
      params: { query: queryParams() },
    })
    rules.value = data?.rules ?? []
    minCorrelated.value = Number(data?.minCorrelated ?? 0)
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

const ready = computed(() => rules.value.filter((r) => r.reading === 'ready'))
const disputed = computed(() => rules.value.filter((r) => r.reading === 'disputed'))
/**
 * Rules that are matching but have not matched enough yet to be judged.
 *
 * Shown because of what happened without them: a rule deployed that morning had matched
 * four requests, all four blocked by F5 — working exactly as intended — and appeared on no
 * page at all, because four is below the floor for a reading. "My new rule is nowhere" and
 * "my new rule matches nothing" look identical from here, and only one of them is a problem.
 */
const accumulating = computed(() => rules.value.filter((r) => r.reading === 'insufficient'))
</script>

<template>
  <div>
    <MigrationStageHeader
      :step="2"
      title="Logging at Cloudflare, blocked by F5"
      definition="A Cloudflare rule matched in log mode and F5 independently blocked the same requests. Both systems are catching the same traffic."
      action="Switch these Cloudflare rules from log to block, then confirm F5 stops seeing the traffic."
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

        <div v-else-if="rules.length === 0" class="py-6 text-center">
          <v-icon icon="mdi-shield-sync-outline" size="32" class="text-medium-emphasis mb-2" />
          <div class="text-body-1">No rule has enough agreement to act on yet.</div>
          <div class="text-body-2 text-medium-emphasis">
            Rules added in step 1 appear here once F5 blocks the same requests. Widening the range
            helps: this is measured on accumulated evidence, not on the last hour.
          </div>
        </div>

        <template v-else>
          <div v-if="ready.length" class="mb-4">
            <div class="text-subtitle-2 mb-1">Ready to enforce</div>
            <RuleAgreementTable
              :rules="ready"
              :range="range"
              :min-correlated="minCorrelated"
              sample-verdict="blocked"
            />
          </div>

          <!-- Kept apart rather than sorted in. A rule that is 60% confirmed is not a
               weaker version of one that is 99% confirmed; it is a different decision,
               and mixing them invites enforcing down the list. -->
          <div v-if="disputed.length" class="mb-4">
            <div class="text-subtitle-2 mb-1">Not yet — the vendors disagree on part of this</div>
            <div class="text-caption text-medium-emphasis mb-1">
              Read the requests before enforcing. Where F5 let something through that the rule
              logged, enforcing would start blocking it.
            </div>
            <RuleAgreementTable
              :rules="disputed"
              :range="range"
              :min-correlated="minCorrelated"
              sample-verdict="allowed"
            />
          </div>

          <!-- Last, and deliberately not silent. These are working rules that have not yet
               been seen often enough to act on. -->
          <div v-if="accumulating.length">
            <div class="text-subtitle-2 mb-1">Still accumulating evidence</div>
            <div class="text-caption text-medium-emphasis mb-1">
              Matching, but on too few requests to judge yet. Widen the range, or come back once the
              traffic has built up — this is what a newly deployed rule looks like.
            </div>
            <RuleAgreementTable
              :rules="accumulating"
              :range="range"
              :min-correlated="minCorrelated"
              sample-verdict="blocked"
            />
          </div>
        </template>
      </v-card-text>
    </v-card>
  </div>
</template>
