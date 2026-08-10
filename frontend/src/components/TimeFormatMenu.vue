<script setup lang="ts">
/**
 * The clock the console reads in.
 *
 * Placed in the app bar rather than buried in a settings page because it is CONTEXT for
 * everything on screen, not a preference someone sets once. An analyst comparing this
 * console against a vendor's needs to know, without navigating away, which zone the
 * timestamps in front of them are in — and to switch it in one click when the answer is
 * "not the one I need".
 */
import { computed } from 'vue'
import { usePreferencesStore } from '@/stores/preferences'
import { COMMON_TIME_ZONES, type HourFormat } from '@/lib/datetime'

const prefs = usePreferencesStore()

/** A sample rendered under the current setting, so the effect is visible before use. */
const sample = computed(() => prefs.dateTime(new Date()))

const HOUR_OPTIONS: { value: HourFormat; label: string }[] = [
  { value: 'auto', label: 'Locale' },
  { value: '24', label: '24-hour' },
  { value: '12', label: '12-hour' },
]

/** The browser's own zone, offered as the first choice and labelled as such. */
const browserZone = computed(() =>
  prefs.followsBrowser ? prefs.activeTimeZone : Intl.DateTimeFormat().resolvedOptions().timeZone,
)

const zones = computed(() => [...COMMON_TIME_ZONES])
</script>

<template>
  <v-menu :close-on-content-click="false" location="bottom end">
    <template #activator="{ props: menuProps }">
      <!-- The active zone is shown ON the activator, not only inside the menu. A
           timestamp whose zone you have to open a menu to learn is still ambiguous. -->
      <v-btn v-bind="menuProps" variant="text" size="small" prepend-icon="mdi-clock-outline">
        {{ prefs.activeTimeZone }}
      </v-btn>
    </template>

    <v-card min-width="300">
      <v-card-text>
        <div class="text-subtitle-2 mb-1">Time display</div>
        <div class="text-caption text-medium-emphasis mb-3">
          Applies to every timestamp in the console. Stored data is unchanged — this changes how
          instants are shown, never what was recorded.
        </div>

        <v-select
          :model-value="prefs.timeZone"
          :items="[{ title: `Browser (${browserZone})`, value: '' }, ...zones]"
          label="Timezone"
          density="compact"
          variant="outlined"
          hide-details
          class="mb-3"
          @update:model-value="prefs.setTimeZone($event ?? '')"
        />

        <v-btn-toggle
          :model-value="prefs.hourFormat"
          density="compact"
          variant="outlined"
          divided
          mandatory
          class="mb-3"
          @update:model-value="prefs.setHourFormat($event)"
        >
          <v-btn
            v-for="option in HOUR_OPTIONS"
            :key="option.value"
            :value="option.value"
            size="small"
          >
            {{ option.label }}
          </v-btn>
        </v-btn-toggle>

        <div class="text-caption text-medium-emphasis">Now shows as</div>
        <div class="text-body-2">{{ sample }}</div>
      </v-card-text>

      <v-card-actions>
        <v-btn size="small" variant="text" @click="prefs.reset()">Use browser default</v-btn>
      </v-card-actions>
    </v-card>
  </v-menu>
</template>
