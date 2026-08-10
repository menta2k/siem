<script setup lang="ts">
/**
 * How long the disk lasts.
 *
 * The question an operator asks before a retention change, a new feed, or a holiday. It
 * is answered here rather than left to a monitoring system because the platform is the
 * thing filling the disk: it knows what it wrote yesterday, and nothing else on the host
 * does.
 */
import { computed } from 'vue'
import type { components } from '@/api/schema'

const props = defineProps<{ storage: components['schemas']['StoragePanel'] | null }>()

/**
 * Byte counts arrive as STRINGS. They are 64-bit on the wire, which exceeds what a JS
 * number holds exactly, so the generator emits them as strings rather than silently
 * losing precision. Coercing is safe for display — a disk size does not need the last
 * byte — but it has to be deliberate rather than accidental.
 */
function num(value?: string | number): number {
  return Number(value ?? 0)
}

/** Renders a byte count at a human scale, stopping where the precision stops meaning. */
function bytes(value?: string | number): string {
  const size = num(value)
  if (size <= 0) return '0 B'

  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  const power = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1)
  const scaled = size / 1024 ** power
  return `${scaled.toFixed(scaled >= 100 || power === 0 ? 0 : 1)} ${units[power]}`
}

const usedBytes = computed(
  () => num(props.storage?.diskTotalBytes) - num(props.storage?.diskFreeBytes),
)

const usedPercent = computed(() => {
  const total = num(props.storage?.diskTotalBytes)
  if (total === 0) return 0
  return Math.min(100, Math.round((usedBytes.value / total) * 100))
})

const days = computed(() => Number(props.storage?.daysRemaining ?? 0))

/**
 * The headline, and the colour that goes with it.
 *
 * Thresholds are days rather than percentages, because a percentage is not actionable:
 * 80% full is comfortable at a gigabyte a day and an emergency at fifty. Two weeks is
 * roughly the notice needed to provision disk or shorten retention deliberately, rather
 * than at 3am.
 */
const headline = computed(() => {
  if (!props.storage) return { text: '—', color: undefined, note: '' }
  if (props.storage.steady) {
    return {
      text: 'No growth measured',
      color: undefined,
      note: 'Nothing was written on the days measured, so there is no rate to project from.',
    }
  }
  if (days.value < 7) return { text: `${days.value.toFixed(1)} days`, color: 'error', note: '' }
  if (days.value < 30) return { text: `${Math.round(days.value)} days`, color: 'warning', note: '' }
  return { text: `${Math.round(days.value)} days`, color: 'success', note: '' }
})

const measured = computed(() => Number(props.storage?.measuredDays ?? 0))

const tables = computed(() => (props.storage?.tables ?? []).slice(0, 6))
</script>

<template>
  <v-card class="mb-4">
    <v-card-title class="text-subtitle-1">
      Storage headroom
      <span class="text-caption text-medium-emphasis ml-2"> at the measured write rate </span>
    </v-card-title>

    <v-card-text v-if="!storage" class="text-body-2 text-medium-emphasis">
      Storage figures are unavailable.
    </v-card-text>

    <v-card-text v-else>
      <div class="d-flex align-baseline ga-2 mb-1">
        <div class="text-h4" :class="headline.color ? `text-${headline.color}` : ''">
          {{ headline.text }}
        </div>
        <div v-if="!storage.steady" class="text-body-2 text-medium-emphasis">until full</div>
      </div>

      <div v-if="headline.note" class="text-caption text-medium-emphasis mb-2">
        {{ headline.note }}
      </div>

      <v-progress-linear
        :model-value="usedPercent"
        :color="headline.color ?? 'primary'"
        height="8"
        rounded
        class="mb-2"
      />

      <div class="text-body-2 mb-3">
        {{ bytes(usedBytes) }} used of {{ bytes(storage.diskTotalBytes) }}
        <span class="text-medium-emphasis">
          ({{ bytes(storage.diskFreeBytes) }} free — this platform holds
          {{ bytes(storage.databaseBytes) }} of it)
        </span>
      </div>

      <div class="text-body-2">
        Writing <strong>{{ bytes(storage.bytesPerDay) }}</strong> per day
        <span class="text-medium-emphasis">
          <template v-if="measured === 0">— no whole day measured yet</template>
          <template v-else-if="measured === 1">
            — measured over 1 whole day, so treat it as provisional
          </template>
          <template v-else>— averaged over {{ measured }} whole days</template>
        </span>
      </div>

      <!--
        Said plainly rather than modelled. Every event table has a retention TTL, so once
        the oldest data reaches it, expiry starts offsetting ingestion and the real
        horizon becomes longer than this. Modelling that would need per-tenant retention
        and ClickHouse's merge schedule — a guess dressed as arithmetic. An operator who
        knows the estimate is conservative can act on it.
      -->
      <div class="text-caption text-medium-emphasis mt-2">
        Straight-line projection: it does not subtract data that retention will expire, so the real
        figure is this or better.
      </div>

      <v-divider class="my-3" />

      <div class="text-caption text-medium-emphasis mb-1">Largest tables</div>
      <v-table density="compact">
        <tbody>
          <tr v-for="table in tables" :key="table.table">
            <td>{{ table.table }}</td>
            <td class="text-right">{{ bytes(table.bytes) }}</td>
            <td class="text-right text-medium-emphasis">{{ table.rows }} rows</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>
