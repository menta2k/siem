<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import type { components } from '@/api/schema'

type EventFilters = components['schemas']['EventFilters']
type EventSummary = components['schemas']['EventSummary']
type Vendor = NonNullable<EventSummary['vendor']>
type Verdict = NonNullable<EventSummary['verdict']>

const props = defineProps<{
  modelValue: EventFilters
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', filters: EventFilters): void
  (e: 'apply'): void
}>()

// A local working copy: filters are applied on submit, not on every keystroke. Firing
// a query per character would put a scan on the cluster for each prefix of what the
// analyst is typing.
const draft = ref<EventFilters>({ ...props.modelValue })

watch(
  () => props.modelValue,
  (next) => {
    draft.value = { ...next }
  },
  { deep: true },
)

const vendorOptions: Array<{ title: string; value: Vendor }> = [
  { title: 'Cloudflare', value: 'VENDOR_CLOUDFLARE' },
  { title: 'F5', value: 'VENDOR_F5' },
  { title: 'DataDome', value: 'VENDOR_DATADOME' },
]

const verdictOptions: Array<{ title: string; value: Verdict }> = [
  { title: 'Allowed', value: 'VERDICT_ALLOWED' },
  { title: 'Blocked', value: 'VERDICT_BLOCKED' },
  { title: 'Challenged', value: 'VERDICT_CHALLENGED' },
  { title: 'Rate limited', value: 'VERDICT_RATE_LIMITED' },
  // Kept distinct from Allowed: a vendor in monitoring mode did not decide to permit
  // the request, and folding them together hides a vendor that was never enforcing.
  { title: 'Monitored', value: 'VERDICT_MONITORED' },
]

const methodOptions = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']

const activeCount = computed(
  () =>
    Object.values(draft.value).filter(
      (v) => v !== undefined && v !== '' && !(Array.isArray(v) && v.length === 0),
    ).length,
)

function apply(): void {
  emit('update:modelValue', { ...draft.value })
  emit('apply')
}

function clear(): void {
  draft.value = {}
  emit('update:modelValue', {})
  emit('apply')
}

/** Parses a numeric input, treating a blank field as "no filter" rather than zero. */
function numberOrUndefined(value: string): number | undefined {
  const trimmed = value.trim()
  if (trimmed === '') return undefined
  const parsed = Number(trimmed)
  return Number.isFinite(parsed) ? parsed : undefined
}
</script>

<template>
  <v-card>
    <v-card-title class="d-flex align-center text-subtitle-1">
      Filters
      <v-chip v-if="activeCount" class="ml-2" size="x-small" color="primary" variant="tonal">
        {{ activeCount }}
      </v-chip>
      <v-spacer />
      <v-btn variant="text" size="small" :disabled="!activeCount" @click="clear">
        Clear
      </v-btn>
    </v-card-title>

    <v-card-text>
      <v-form @submit.prevent="apply">
        <v-text-field
          v-model="draft.q"
          label="Search text"
          hint="Matches whole words in the request path"
          persistent-hint
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-select
          v-model="draft.vendor"
          :items="vendorOptions"
          label="Vendor"
          multiple
          chips
          closable-chips
          density="compact"
          variant="outlined"
          class="mb-3"
        />

        <v-select
          v-model="draft.verdict"
          :items="verdictOptions"
          label="Verdict"
          multiple
          chips
          closable-chips
          density="compact"
          variant="outlined"
          class="mb-3"
        />

        <v-text-field
          v-model="draft.clientIp"
          label="Client IP"
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-text-field
          v-model="draft.requestHost"
          label="Host"
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-text-field
          v-model="draft.requestPath"
          label="Path"
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-select
          v-model="draft.requestMethod"
          :items="methodOptions"
          label="Method"
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-text-field
          v-model="draft.ruleId"
          label="Rule"
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-text-field
          v-model="draft.userAgent"
          label="User agent"
          hint="Matches whole words"
          persistent-hint
          density="compact"
          variant="outlined"
          clearable
          class="mb-3"
        />

        <v-row dense>
          <v-col cols="6">
            <v-text-field
              :model-value="draft.minScore"
              label="Min score"
              type="number"
              step="0.01"
              density="compact"
              variant="outlined"
              @update:model-value="draft.minScore = numberOrUndefined($event)"
            />
          </v-col>
          <v-col cols="6">
            <v-text-field
              :model-value="draft.maxScore"
              label="Max score"
              type="number"
              step="0.01"
              density="compact"
              variant="outlined"
              @update:model-value="draft.maxScore = numberOrUndefined($event)"
            />
          </v-col>
        </v-row>

        <v-row dense>
          <v-col cols="6">
            <v-text-field
              v-model="draft.country"
              label="Country"
              density="compact"
              variant="outlined"
              clearable
            />
          </v-col>
          <v-col cols="6">
            <v-text-field
              :model-value="draft.asn"
              label="ASN"
              type="number"
              density="compact"
              variant="outlined"
              @update:model-value="draft.asn = numberOrUndefined($event)"
            />
          </v-col>
        </v-row>

        <v-btn type="submit" color="primary" block class="mt-3">Search</v-btn>
      </v-form>
    </v-card-text>
  </v-card>
</template>
