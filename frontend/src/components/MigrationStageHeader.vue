<script setup lang="ts">
/**
 * The band every migration stage carries: what this stage means, and the two controls
 * that scope it.
 *
 * The explanation is not decoration. Each stage is defined by a PAIR of verdicts on the
 * same request, and a reader who has the pair backwards will draw the opposite
 * conclusion from the same table — so the definition sits above the numbers rather than
 * in documentation nobody opens next to a worklist.
 */
import { MIGRATION_RANGES } from '@/composables/useMigrationRange'

defineProps<{
  /** Which stage of the move this is, shown as "Step N of 3". */
  step: number
  title: string
  /** The pair of verdicts that defines the stage, in plain words. */
  definition: string
  /** What the reader is expected to DO with a row here. */
  action: string
  rangeHours: number
  host: string
  loading?: boolean
}>()

const emit = defineEmits<{
  'update:rangeHours': [value: number]
  'update:host': [value: string]
  reload: []
}>()
</script>

<template>
  <v-card class="mb-4">
    <v-card-text>
      <div class="d-flex align-start flex-wrap ga-4">
        <div class="flex-grow-1">
          <div class="text-overline text-medium-emphasis">Step {{ step }} of 3</div>
          <div class="text-subtitle-1">{{ title }}</div>
          <div class="text-body-2 text-medium-emphasis mt-1">{{ definition }}</div>
          <div class="text-body-2 mt-1">
            <v-icon icon="mdi-arrow-right-thin" size="small" class="mr-1" />{{ action }}
          </div>
        </div>

        <div class="controls d-flex flex-column ga-2">
          <v-select
            :model-value="rangeHours"
            :items="MIGRATION_RANGES"
            density="compact"
            variant="outlined"
            hide-details
            label="Range"
            @update:model-value="emit('update:rangeHours', $event)"
          />
          <!-- A migration is run site by site, so the host is a first-class control
               rather than something to scan for. Sent to the server, before the limit. -->
          <v-text-field
            :model-value="host"
            density="compact"
            variant="outlined"
            hide-details
            clearable
            label="Host"
            placeholder="all sites"
            @update:model-value="emit('update:host', $event ?? '')"
            @keyup.enter="emit('reload')"
          />
          <v-btn
            size="small"
            variant="tonal"
            :loading="loading"
            prepend-icon="mdi-refresh"
            @click="emit('reload')"
          >
            Apply
          </v-btn>
        </div>
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.controls {
  min-width: 14rem;
}
</style>
