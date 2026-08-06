<script setup lang="ts">
import { computed } from 'vue'
import type { components } from '@/api/schema'

type EventSummary = components['schemas']['EventSummary']

const props = defineProps<{
  items: EventSummary[]
  loading?: boolean
  hasMore?: boolean
  total?: number
  totalIsEstimate?: boolean
}>()

const emit = defineEmits<{
  (e: 'loadMore'): void
  (e: 'select', item: EventSummary): void
}>()

const vendorLabels: Record<string, string> = {
  VENDOR_CLOUDFLARE: 'Cloudflare',
  VENDOR_F5: 'F5',
  VENDOR_DATADOME: 'DataDome',
}

const verdictStyles: Record<string, { label: string; color: string }> = {
  VERDICT_ALLOWED: { label: 'Allowed', color: 'success' },
  VERDICT_BLOCKED: { label: 'Blocked', color: 'error' },
  VERDICT_CHALLENGED: { label: 'Challenged', color: 'warning' },
  VERDICT_RATE_LIMITED: { label: 'Rate limited', color: 'warning' },
  VERDICT_MONITORED: { label: 'Monitored', color: 'info' },
  VERDICT_UNKNOWN: { label: 'Unknown', color: 'grey' },
}

function verdictOf(item: EventSummary) {
  return verdictStyles[item.verdict ?? ''] ?? { label: 'Not reported', color: 'grey' }
}

function formatTime(value?: string): string {
  return value ? new Date(value).toLocaleString() : '—'
}

const countLabel = computed(() => {
  const shown = props.items.length
  if (props.totalIsEstimate) return `${shown} shown, more available`
  return `${shown} of ${props.total ?? shown}`
})
</script>

<template>
  <div>
    <div class="d-flex align-center justify-space-between mb-2">
      <div class="text-body-2 text-medium-emphasis">{{ countLabel }}</div>
      <v-progress-circular v-if="loading" indeterminate size="20" width="2" />
    </div>

    <!--
      EVERY log-derived value below is rendered as TEXT through Vue's interpolation,
      which HTML-escapes. Nothing here uses v-html, and eslint enforces that
      (vue/no-v-html is an error, not a warning).

      This is the release-blocking property of this component: user agents, paths, and
      rule names are attacker-controlled by definition. An attacker who can make a
      request to a customer's site can put a payload in a header, and this console is
      where a defender reads it back.
    -->
    <v-table density="compact" fixed-header height="60vh">
      <thead>
        <tr>
          <th>Time</th>
          <th>Vendor</th>
          <th>Verdict</th>
          <th>Client</th>
          <th>Request</th>
          <th>Rule</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="item in items"
          :key="item.eventId"
          class="event-row"
          tabindex="0"
          @click="emit('select', item)"
          @keydown.enter="emit('select', item)"
        >
          <td class="text-no-wrap">{{ formatTime(item.eventTime) }}</td>
          <td>{{ vendorLabels[item.vendor ?? ''] ?? 'Unknown' }}</td>
          <td>
            <v-chip :color="verdictOf(item).color" size="x-small" variant="tonal">
              {{ verdictOf(item).label }}
            </v-chip>
          </td>
          <td class="text-no-wrap">
            <code>{{ item.client?.ip || '—' }}</code>
            <span v-if="item.client?.country" class="text-caption text-medium-emphasis ml-1">
              {{ item.client.country }}
            </span>
          </td>
          <td class="request-cell">
            <code>{{ item.request?.method }} {{ item.request?.host }}{{ item.request?.path }}</code>
          </td>
          <td>{{ item.ruleId || '—' }}</td>
          <td>{{ typeof item.score === 'number' ? item.score.toFixed(2) : '—' }}</td>
        </tr>

        <tr v-if="!items.length && !loading">
          <td colspan="7" class="text-center text-medium-emphasis py-8">
            No events matched. Widen the time range or clear a filter.
          </td>
        </tr>
      </tbody>
    </v-table>

    <!--
      Explicit "load more" rather than infinite scroll. A cursor page is a point-in-time
      slice, and auto-loading while an analyst reads makes it impossible to tell whether
      the list changed because they scrolled or because the data did.
    -->
    <div v-if="hasMore" class="d-flex justify-center mt-3">
      <v-btn variant="tonal" :loading="loading" @click="emit('loadMore')">
        Load more
      </v-btn>
    </div>
  </div>
</template>

<style scoped>
.event-row {
  cursor: pointer;
}

/*
 * Long paths are truncated visually, never in the data. The full value stays in the
 * DOM as text so it is selectable and searchable — clipping the string itself would
 * hide the tail of an attack payload, which is exactly the part worth reading.
 */
.request-cell code {
  display: inline-block;
  max-width: 42ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
}
</style>
