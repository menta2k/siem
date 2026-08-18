<script setup lang="ts">
import { computed } from 'vue'
import { usePreferencesStore } from '@/stores/preferences'

const prefs = usePreferencesStore()

interface Health {
  status?: string
  eventsFiled?: string | number
  recordsEmitted?: string | number
  windowsDroppedEmpty?: string | number
  windowsDue?: string | number
  claimLagMs?: string | number
  windowTtlMs?: string | number
  lastRecordAt?: string
}

const props = defineProps<{ health?: Health | null }>()

function count(value: string | number | undefined): number {
  return Number(value ?? 0)
}

/**
 * One chip, one state, decided by the SERVER.
 *
 * The status string is rendered rather than recomputed here: the same counters are read
 * by the API and would otherwise be judged twice, and the two would disagree the first
 * time either was edited. This maps the server's word onto how urgently it reads.
 */
const status = computed(() => {
  switch (props.health?.status) {
    case 'failing':
      return { label: 'Failing', color: 'error', icon: 'mdi-close-octagon' }
    case 'stalled':
      return { label: 'Stalled', color: 'error', icon: 'mdi-pause-octagon' }
    case 'losing':
      return { label: 'Losing correlations', color: 'error', icon: 'mdi-alert-octagon' }
    case 'behind':
      return { label: 'Behind', color: 'warning', icon: 'mdi-clock-alert' }
    case 'healthy':
      return { label: 'Healthy', color: 'success', icon: 'mdi-check-circle' }
    case 'idle':
      return { label: 'Idle', color: 'secondary', icon: 'mdi-timer-sand' }
    default:
      return { label: 'Unavailable', color: 'grey', icon: 'mdi-help-circle-outline' }
  }
})

function minutes(ms: string | number | undefined): string {
  return `${Math.round(count(ms) / 60000)} min`
}

/**
 * The tooltip says what to DO, because the chip alone cannot. "Stalled" is only
 * actionable once you know that events are still arriving and nothing is coming out.
 */
const tooltip = computed(() => {
  const filed = count(props.health?.eventsFiled).toLocaleString()
  const last = props.health?.lastRecordAt
    ? `Last record ${prefs.dateTime(props.health.lastRecordAt)}.`
    : 'No record has been written in this window.'

  switch (props.health?.status) {
    case 'failing':
      return `Every close pass is erroring and nothing is being written. ${filed} events were filed. Check the processor log.`
    case 'stalled':
      return `${filed} events were filed and no correlated records came out. ${last}`
    case 'losing':
      return `Windows are being closed after their state expired, so those events will never be correlated: ${count(props.health?.windowsDroppedEmpty).toLocaleString()} so far. The closer is behind by ${minutes(props.health?.claimLagMs)} against a window lifetime of ${minutes(props.health?.windowTtlMs)}.`
    case 'behind':
      return `Still emitting, but claims are ${minutes(props.health?.claimLagMs)} behind against a window lifetime of ${minutes(props.health?.windowTtlMs)}, with ${count(props.health?.windowsDue).toLocaleString()} windows waiting. Past that lifetime, windows close empty and correlations are lost.`
    case 'healthy':
      return `${filed} events filed, ${count(props.health?.recordsEmitted).toLocaleString()} correlated records written. ${last}`
    case 'idle':
      return 'No events were filed for correlation in this window, so there is nothing to judge.'
    default:
      return 'The pipeline has not reported its health. It may be running a build that predates this panel.'
  }
})
</script>

<template>
  <v-tooltip :text="tooltip" location="top" max-width="420">
    <template #activator="{ props: tooltipProps }">
      <v-chip v-bind="tooltipProps" :color="status.color" size="small" variant="tonal">
        <v-icon :icon="status.icon" start size="small" />
        {{ status.label }}
      </v-chip>
    </template>
  </v-tooltip>
</template>
