<script setup lang="ts">
import { ref, watch } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { operations } from '@/api/schema'

/** The query this endpoint accepts, named so the literal below is checked against it. */
type RejectedQuery = NonNullable<operations['Feeds_ListRejectedEvents']['parameters']['query']>

const props = defineProps<{ feedId: string | null }>()
const emit = defineEmits<{ close: [] }>()

interface RejectedEvent {
  rejectedAt?: string
  vendor?: string
  reasonCode?: string
  reasonDetail?: string
  payload?: string
  batchId?: string
}

const events = ref<RejectedEvent[]>([])
const loading = ref(false)
const errorMessage = ref('')
const reasonFilter = ref<string | null>(null)

// The codes the backend can emit. Kept in step with the ingest contract's enum.
const reasonOptions = [
  { title: 'All reasons', value: null },
  { title: 'Parse error', value: 'PARSE_ERROR' },
  { title: 'Timestamp out of range', value: 'TIMESTAMP_OUT_OF_RANGE' },
  { title: 'Unknown schema', value: 'SCHEMA_UNKNOWN' },
  { title: 'Quota exceeded', value: 'QUOTA_EXCEEDED' },
  { title: 'Payload too large', value: 'PAYLOAD_TOO_LARGE' },
]

async function load(): Promise<void> {
  if (!props.feedId) return

  loading.value = true
  errorMessage.value = ''
  try {
    // The API requires an explicit time range — an unbounded query is not expressible.
    const to = new Date()
    const from = new Date(to.getTime() - 24 * 60 * 60 * 1000)

    const query: RejectedQuery = {
      'range.from': from.toISOString(),
      'range.to': to.toISOString(),
    }
    // Assigned rather than spread, so the literal stays excess-property checked.
    if (reasonFilter.value) query.reasonCode = reasonFilter.value

    const { data } = await api.GET('/api/v1/feeds/{feedId}/rejected', {
      params: {
        path: { feedId: props.feedId },
        query,
      },
    })
    events.value = data?.events ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

watch(() => props.feedId, load, { immediate: true })
watch(reasonFilter, load)

function reasonColor(code: string | undefined): string {
  switch (code) {
    case 'PARSE_ERROR':
      return 'error'
    case 'TIMESTAMP_OUT_OF_RANGE':
      return 'warning'
    case 'QUOTA_EXCEEDED':
      return 'info'
    default:
      return 'secondary'
  }
}
</script>

<template>
  <v-dialog
    :model-value="feedId !== null"
    max-width="1000"
    scrollable
    @update:model-value="emit('close')"
  >
    <v-card>
      <v-card-title class="d-flex align-center">
        <span>Rejected events</span>
        <v-spacer />
        <v-select
          v-model="reasonFilter"
          :items="reasonOptions"
          density="compact"
          hide-details
          style="max-width: 260px"
        />
      </v-card-title>

      <v-card-subtitle class="pb-2">
        Deliveries the platform could not accept, with the reason. Nothing is dropped silently —
        every rejection appears here.
      </v-card-subtitle>

      <v-divider />

      <v-card-text style="max-height: 60vh">
        <v-alert v-if="errorMessage" type="error" variant="tonal" density="compact" class="mb-4">
          {{ errorMessage }}
        </v-alert>

        <v-progress-linear v-if="loading" indeterminate />

        <div v-else-if="!events.length" class="pa-8 text-center text-medium-emphasis">
          No rejections in the last 24 hours.
        </div>

        <v-expansion-panels v-else variant="accordion">
          <v-expansion-panel v-for="(event, index) in events" :key="index">
            <v-expansion-panel-title>
              <div class="d-flex align-center ga-3" style="width: 100%">
                <v-chip :color="reasonColor(event.reasonCode)" size="small" variant="tonal">
                  {{ event.reasonCode }}
                </v-chip>
                <span class="text-body-2 text-medium-emphasis">
                  {{ event.rejectedAt ? new Date(event.rejectedAt).toLocaleString() : '' }}
                </span>
                <span class="text-body-2 text-truncate">{{ event.reasonDetail }}</span>
              </div>
            </v-expansion-panel-title>

            <v-expansion-panel-text>
              <div class="text-caption text-medium-emphasis mb-1">Reason</div>
              <div class="text-body-2 mb-4">{{ event.reasonDetail }}</div>

              <div class="text-caption text-medium-emphasis mb-1">
                Payload as delivered by the vendor
              </div>
              <!--
                Attacker-controlled content. Rendered through text interpolation only —
                never v-html, which the lint rule forbids outright.
              -->
              <pre class="payload">{{ event.payload }}</pre>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-card-text>

      <v-divider />
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="emit('close')">Close</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<style scoped>
.payload {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.8rem;
  white-space: pre-wrap;
  word-break: break-all;
  padding: 0.75rem;
  border-radius: 4px;
  background: rgba(127, 127, 127, 0.12);
  max-height: 300px;
  overflow: auto;
}
</style>
