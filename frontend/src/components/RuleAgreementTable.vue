<script setup lang="ts">
/**
 * One Cloudflare rule per row, measured against what F5 did with the same requests.
 *
 * Shared by stages 2 and 3 because they are ONE measurement read from opposite ends: the
 * rules F5 confirms and the rules F5 contradicts. Two components would be two definitions
 * of agreement, and they would eventually disagree about the same rule.
 *
 * THE THREE F5 COUNTS ARE SHOWN SEPARATELY, always. F5 has a transparent mode of its own,
 * and a request it flagged without blocking is weaker evidence than one it stopped and
 * stronger than one it ignored. A single "agreement %" would bury exactly that.
 */
import { ref } from 'vue'
import type { components } from '@/api/schema'
import { usePreferencesStore } from '@/stores/preferences'
import type { MigrationRange } from '@/composables/useMigrationRange'
import MigrationSamples from '@/components/MigrationSamples.vue'

type RuleAgreement = components['schemas']['WafRuleAgreement']

const props = defineProps<{
  rules: RuleAgreement[]
  range: MigrationRange
  /** Which side of the disagreement this stage drills into. */
  sampleVerdict: 'blocked' | 'allowed'
  /**
   * How many correlated requests a rule needs before it is judged at all.
   *
   * Comes from the server, which is also where the threshold is applied. Hardcoding it here
   * would let the number a reader is shown drift from the number the query used.
   */
  minCorrelated?: number
}>()

const prefs = usePreferencesStore()
const expanded = ref<string | null>(null)

function toggle(rule: RuleAgreement): void {
  expanded.value = expanded.value === rule.ruleId ? null : (rule.ruleId ?? null)
}

/** The reading is computed server-side; this only translates it for a reader. */
const READINGS: Record<string, { label: string; colour: string; hint: string }> = {
  ready: {
    label: 'ready to enforce',
    colour: 'success',
    hint: 'F5 blocks nearly everything this rule logs',
  },
  disputed: {
    label: 'needs a look',
    colour: 'warning',
    hint: 'the two vendors genuinely disagree on a share of these requests',
  },
  false_positive: {
    label: 'likely false positive',
    colour: 'error',
    hint: 'F5 lets through nearly everything this rule logs',
  },
  insufficient: {
    label: 'too few requests yet',
    colour: 'default',
    hint: 'not a judgement on the rule — just not enough requests to make one',
  },
}

/**
 * How a rule's reading is shown.
 *
 * `insufficient` is rendered as PROGRESS rather than as a verdict — "8 of 10" — because the
 * old wording, "not enough evidence", said only that something was missing and never what
 * or how much. The author of a working rule read it as a criticism of the rule.
 */
function reading(rule: RuleAgreement) {
  const base = READINGS[rule.reading ?? ''] ?? READINGS.insufficient
  if (rule.reading !== 'insufficient' || !props.minCorrelated) return base

  // Progress only makes sense below the bar. A rule the server left unjudged while sitting
  // above it is something else, and "147 of 10" would be nonsense.
  const seen = Number(rule.correlated ?? 0)
  if (seen >= props.minCorrelated) return base

  return {
    ...base,
    label: `${seen} of ${props.minCorrelated} requests`,
    hint:
      `A reading needs ${props.minCorrelated} requests that both vendors saw; this rule ` +
      `has ${seen}. It is matching — the counts beside it are real — and will be judged ` +
      `once the traffic builds up.`,
  }
}

/**
 * Share of the group each count holds, for the proportion bar.
 *
 * The counts arrive as STRINGS: they are uint64 on the wire, which JSON cannot carry as a
 * number without losing precision, so the generated client types them as strings and
 * every arithmetic use has to convert first.
 */
function share(rule: RuleAgreement, count?: string | number): number {
  const total = Number(rule.correlated ?? 0)
  if (!total) return 0
  return (Number(count ?? 0) / total) * 100
}
</script>

<template>
  <v-table density="compact">
    <thead>
      <tr>
        <th>Cloudflare rule</th>
        <th>Host</th>
        <th class="text-right">Correlated</th>
        <!-- Never merged: see the component comment. -->
        <th class="text-right">F5 blocked</th>
        <th class="text-right">F5 flagged</th>
        <th class="text-right">F5 allowed</th>
        <th>Reading</th>
        <th>Last seen</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      <template v-for="rule in props.rules" :key="rule.ruleId">
        <tr class="row-clickable" @click="toggle(rule)">
          <td>
            <!-- The name first: a 32-character hex id is unreadable in a decision this
                 consequential. The id stays beneath it, because that is what an operator
                 pastes into the Cloudflare dashboard. -->
            <div v-if="rule.ruleDescription">{{ rule.ruleDescription }}</div>
            <code class="text-caption text-medium-emphasis">{{ rule.ruleId }}</code>
          </td>
          <td class="text-caption">
            {{ rule.requestHost || `${rule.hosts} hosts` }}
          </td>
          <td class="text-right">{{ Number(rule.correlated ?? 0).toLocaleString() }}</td>
          <td class="text-right">{{ Number(rule.f5Blocked ?? 0).toLocaleString() }}</td>
          <td class="text-right text-medium-emphasis">
            {{ Number(rule.f5Flagged ?? 0).toLocaleString() }}
          </td>
          <td class="text-right">{{ Number(rule.f5Allowed ?? 0).toLocaleString() }}</td>
          <td>
            <v-chip :color="reading(rule)?.colour" size="x-small" variant="tonal">
              {{ reading(rule)?.label }}
            </v-chip>
            <!-- The proportion, drawn. Three numbers in a row are read as three numbers;
                 the split is the finding. -->
            <div class="split mt-1">
              <span class="seg blocked" :style="{ width: `${share(rule, rule.f5Blocked)}%` }" />
              <span class="seg flagged" :style="{ width: `${share(rule, rule.f5Flagged)}%` }" />
              <span class="seg allowed" :style="{ width: `${share(rule, rule.f5Allowed)}%` }" />
            </div>
          </td>
          <td class="text-caption text-no-wrap">{{ prefs.dateTime(rule.lastSeen) }}</td>
          <td class="text-right">
            <v-icon
              :icon="expanded === rule.ruleId ? 'mdi-chevron-up' : 'mdi-chevron-down'"
              size="small"
            />
          </td>
        </tr>
        <tr v-if="expanded === rule.ruleId">
          <td colspan="9" class="pa-0">
            <div class="text-caption text-medium-emphasis px-3 pt-2">
              {{ reading(rule)?.hint }}
            </div>
            <!-- Cloudflare is monitoring on both of these stages by definition: a rule
                 already blocking is not a migration candidate and never reaches here. -->
            <MigrationSamples
              :range="props.range"
              :rule-id="rule.ruleId"
              :f5-verdict="props.sampleVerdict"
              cloudflare-verdict="monitored"
            />
          </td>
        </tr>
      </template>
    </tbody>
  </v-table>
</template>

<style scoped>
.row-clickable {
  cursor: pointer;
}

.split {
  display: flex;
  width: 7rem;
  height: 4px;
  border-radius: 2px;
  overflow: hidden;
  background: rgba(var(--v-theme-on-surface), 0.08);
}

.seg {
  height: 100%;
}

.blocked {
  background: rgb(var(--v-theme-success));
}

.flagged {
  background: rgb(var(--v-theme-warning));
}

.allowed {
  background: rgb(var(--v-theme-error));
}
</style>
