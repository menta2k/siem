<script setup lang="ts">
/**
 * Editor for the rules that stop events being ingested at all.
 *
 * This screen deletes data. A matched event is written NOWHERE — no raw payload, no
 * searchable row, no rejection — so there is no undo and nothing to recover from, which
 * is not true of any other setting in this console. The design follows from that: each
 * rule reads back as a sentence, rules broad enough to swallow a whole feed are called
 * out before saving, and the consequence is stated on screen rather than assumed known.
 */
import {
  FILTER_FIELDS,
  FILTER_OPERATORS,
  MAX_RULES,
  describeRule,
  isComplete,
  overlyBroad,
  type IngestFilterRule,
} from '@/lib/ingest-filters'

const rules = defineModel<IngestFilterRule[]>({ required: true })

defineProps<{ saving: boolean; disabled: boolean }>()
const emit = defineEmits<{ save: [] }>()

function addRule(): void {
  if (rules.value.length >= MAX_RULES) return
  // Replaced rather than mutated: the parent holds this array, and editing it in place
  // hides the change from anything watching for one.
  rules.value = [...rules.value, { field: 'request_path', op: 'suffix', values: [] }]
}

function removeRule(index: number): void {
  rules.value = rules.value.filter((_, i) => i !== index)
}

function updateRule(index: number, changes: Partial<IngestFilterRule>): void {
  rules.value = rules.value.map((rule, i) => (i === index ? { ...rule, ...changes } : rule))
}
</script>

<template>
  <v-card variant="outlined">
    <v-card-title class="text-subtitle-1">Ingest filters</v-card-title>
    <v-card-subtitle>
      Events matching any rule are discarded on arrival and never stored.
    </v-card-subtitle>

    <v-card-text>
      <v-alert type="warning" variant="tonal" density="comfortable" class="mb-4">
        <strong>Filtered events cannot be recovered.</strong>
        They are not searchable, not counted in dashboards and not kept as raw payloads —
        the only record is the filtered count on the feed's health. Rules apply to events
        arriving from now on and never to what is already stored.
      </v-alert>

      <p v-if="rules.length === 0" class="text-medium-emphasis mb-4">
        No filters. Every event this tenant receives is ingested.
      </p>

      <div v-for="(rule, index) in rules" :key="index" class="mb-4">
        <v-row dense align="center">
          <v-col cols="12" sm="3">
            <v-select
              :model-value="rule.field"
              :items="[...FILTER_FIELDS]"
              item-title="title"
              item-value="value"
              label="Field"
              density="compact"
              hide-details
              :disabled="disabled"
              @update:model-value="updateRule(index, { field: $event })"
            />
          </v-col>
          <v-col cols="12" sm="3">
            <v-select
              :model-value="rule.op"
              :items="[...FILTER_OPERATORS]"
              item-title="title"
              item-value="value"
              label="Condition"
              density="compact"
              hide-details
              :disabled="disabled"
              @update:model-value="updateRule(index, { op: $event })"
            />
          </v-col>
          <v-col cols="12" sm="5">
            <!-- Multiple values are alternatives: any one of them drops the event. -->
            <v-combobox
              :model-value="rule.values ?? []"
              label="Values"
              hint="Press Enter after each. Any one matching is enough."
              persistent-hint
              multiple
              chips
              closable-chips
              density="compact"
              :disabled="disabled"
              @update:model-value="updateRule(index, { values: $event })"
            />
          </v-col>
          <v-col cols="12" sm="1" class="text-right">
            <v-btn
              icon="mdi-delete-outline"
              variant="text"
              size="small"
              :disabled="disabled"
              :aria-label="`Remove rule ${index + 1}`"
              @click="removeRule(index)"
            />
          </v-col>
        </v-row>

        <!-- The sentence is the check. Three dropdowns can be individually right and
             still combine into something the operator did not mean. -->
        <p
          class="text-caption mt-1"
          :class="isComplete(rule) ? 'text-medium-emphasis' : 'text-warning'"
        >
          {{ describeRule(rule) }}
        </p>
        <v-alert
          v-if="overlyBroad(rule)"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-2"
        >
          This matches nearly every request for this tenant. Saving it will discard almost
          all incoming events.
        </v-alert>
      </div>

      <v-btn
        variant="tonal"
        size="small"
        prepend-icon="mdi-plus"
        :disabled="disabled || rules.length >= MAX_RULES"
        @click="addRule"
      >
        Add rule
      </v-btn>
      <span v-if="rules.length >= MAX_RULES" class="text-caption text-medium-emphasis ml-2">
        Maximum of {{ MAX_RULES }} rules reached.
      </span>
    </v-card-text>

    <v-card-actions>
      <v-btn color="primary" :loading="saving" :disabled="disabled" @click="emit('save')">
        Save filters
      </v-btn>
    </v-card-actions>
  </v-card>
</template>
