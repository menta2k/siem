<script setup lang="ts">
import { computed } from 'vue'

interface Health {
  silent?: boolean
  credentialValid?: boolean
  schemaDriftWarning?: boolean
  lastEventAt?: string
  eventsRejected1h?: string | number
}

const props = defineProps<{
  health?: Health | null
  enabled: boolean
}>()

/**
 * One chip, one state — ordered by how urgently an operator needs to act.
 *
 * An invalid credential outranks silence because silence is its consequence: showing
 * "silent" when the real problem is a rotated token sends someone to check the
 * vendor's dashboard instead of fixing the credential.
 */
const status = computed(() => {
  if (!props.enabled) {
    return { label: 'Disabled', color: 'grey', icon: 'mdi-pause-circle' }
  }
  if (props.health?.credentialValid === false) {
    return { label: 'Credential rejected', color: 'error', icon: 'mdi-key-alert' }
  }
  if (props.health?.silent) {
    return { label: 'Silent', color: 'warning', icon: 'mdi-volume-off' }
  }
  if (props.health?.schemaDriftWarning) {
    return { label: 'Schema drift', color: 'info', icon: 'mdi-alert-circle-outline' }
  }
  if (!props.health?.lastEventAt) {
    return { label: 'Awaiting first event', color: 'secondary', icon: 'mdi-timer-sand' }
  }
  return { label: 'Healthy', color: 'success', icon: 'mdi-check-circle' }
})

const tooltip = computed(() => {
  if (!props.enabled) return 'This feed is disabled and will reject deliveries.'
  if (props.health?.credentialValid === false) {
    return 'A delivery was refused because the credential did not authenticate. Rotate it.'
  }
  if (props.health?.silent) {
    return 'Nothing has arrived for over 15 minutes. A silent feed looks identical to clean traffic on a dashboard.'
  }
  if (props.health?.schemaDriftWarning) {
    return 'The vendor is sending fields we do not recognise. Ingestion continues; the new fields are preserved.'
  }
  if (!props.health?.lastEventAt) return 'Configured, but no events have arrived yet.'
  return `Last event ${new Date(props.health.lastEventAt).toLocaleString()}`
})
</script>

<template>
  <v-tooltip :text="tooltip" location="top">
    <template #activator="{ props: tooltipProps }">
      <v-chip v-bind="tooltipProps" :color="status.color" size="small" variant="tonal">
        <v-icon :icon="status.icon" start size="small" />
        {{ status.label }}
      </v-chip>
    </template>
  </v-tooltip>
</template>
