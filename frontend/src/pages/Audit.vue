<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components, operations } from '@/api/schema'
import { usePreferencesStore } from '@/stores/preferences'

const prefs = usePreferencesStore()

type AuditEntry = components['schemas']['AuditEntry']

/**
 * The query this endpoint accepts, taken from the generated contract.
 *
 * Named explicitly so the object below is CHECKED against it. An inline literal with
 * spreads in it is not: TypeScript drops excess-property checking for those, which is
 * how `timeRange.from` — the right name on every other endpoint, and meaningless on
 * this one — reached production without the build noticing.
 */
type AuditQuery = NonNullable<operations['Admin_ListAuditEntries']['parameters']['query']>

const entries = ref<AuditEntry[]>([])
const loading = ref(false)
const errorMessage = ref('')
const days = ref(7)

const actionFilter = ref('')
const actorFilter = ref('')

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''

  const to = new Date()
  const from = new Date(to.getTime() - days.value * 24 * 60 * 60 * 1000)

  // `range`, NOT `timeRange`. This endpoint's request message names the field `range`
  // while every other one names it `time_range`, so the parameter that works everywhere
  // else silently does nothing here — the server saw no range at all and refused the
  // query as unbounded, which read as the audit trail being broken rather than as the
  // console having asked wrongly.
  const query: AuditQuery = {
    'range.from': from.toISOString(),
    'range.to': to.toISOString(),
  }
  // Assigned rather than spread, so the literal above stays checkable.
  if (actionFilter.value) query.action = actionFilter.value
  if (actorFilter.value) query.actorEmail = actorFilter.value

  try {
    const { data } = await api.GET('/api/v1/audit', { params: { query } })
    entries.value = data?.entries ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

/**
 * Hash-chain verification.
 *
 * Each entry carries the hash of the one before it. Verifying the LINKAGE here proves
 * no entry was removed from the middle of the range: a deletion breaks the chain at
 * the point it happened, and that is exactly what an auditor is looking for.
 *
 * What this cannot prove is that the whole range was not rewritten from the start —
 * that needs the anchor the server holds. So the status says "linked", not "authentic",
 * because claiming more than the check establishes is worse than claiming less.
 */
const chainStatus = computed(() => {
  if (!entries.value.length) return { label: 'No entries', color: 'grey', icon: 'mdi-minus' }

  for (let i = 1; i < entries.value.length; i += 1) {
    const previous = entries.value[i - 1]
    const current = entries.value[i]
    if (!current?.previousHash || current.previousHash !== previous?.entryHash) {
      return {
        label: `Chain broken at entry ${i + 1}`,
        color: 'error',
        icon: 'mdi-link-variant-off',
      }
    }
  }

  return {
    label: `${entries.value.length} entries, chain intact`,
    color: 'success',
    icon: 'mdi-link-variant',
  }
})

function formatTime(value?: string): string {
  return prefs.dateTime(value)
}

/** Truncates a hash for display; the full value stays in the title attribute. */
function shortHash(hash?: string): string {
  return hash ? `${hash.slice(0, 12)}…` : '—'
}
</script>

<template>
  <div>
    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <v-card class="mb-4">
      <v-card-text class="d-flex flex-wrap align-center ga-3">
        <v-chip :color="chainStatus.color" variant="tonal">
          <v-icon :icon="chainStatus.icon" start size="small" />
          {{ chainStatus.label }}
        </v-chip>

        <v-spacer />

        <v-text-field
          v-model="actionFilter"
          label="Action"
          density="compact"
          variant="outlined"
          hide-details
          clearable
          style="max-width: 220px"
          @keyup.enter="load"
        />
        <v-text-field
          v-model="actorFilter"
          label="Actor"
          density="compact"
          variant="outlined"
          hide-details
          clearable
          style="max-width: 240px"
          @keyup.enter="load"
        />
        <v-select
          v-model="days"
          :items="[1, 7, 30, 90]"
          label="Days"
          density="compact"
          variant="outlined"
          hide-details
          style="max-width: 110px"
          @update:model-value="load"
        />
        <v-btn variant="text" size="small" :loading="loading" @click="load">Apply</v-btn>
      </v-card-text>
    </v-card>

    <v-progress-linear v-if="loading" indeterminate class="mb-4" />

    <!--
      Read-only by construction: there is no control on this page that writes anything.
      The audit trail is the record an auditor checks the platform against, and a
      console that could edit it would make the record worth nothing.
    -->
    <v-card>
      <v-table density="compact" fixed-header height="70vh">
        <thead>
          <tr>
            <th>When</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Result</th>
            <th>Detail</th>
            <th>Hash</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="entry in entries" :key="entry.entryId">
            <td class="text-no-wrap">{{ formatTime(entry.occurredAt) }}</td>
            <td>{{ entry.actorEmail || 'system' }}</td>
            <td>
              <code>{{ entry.action }}</code>
            </td>
            <td>
              {{ entry.targetType }}
              <code v-if="entry.targetId" class="text-caption">{{ entry.targetId }}</code>
            </td>
            <td>
              <v-chip
                :color="entry.result === 'denied' ? 'error' : 'success'"
                size="x-small"
                variant="tonal"
              >
                {{ entry.result }}
              </v-chip>
            </td>
            <!-- Rendered as text: audit details include operator-supplied notes. -->
            <td class="detail-cell">{{ entry.detail || '—' }}</td>
            <td :title="entry.entryHash">
              <code class="text-caption">{{ shortHash(entry.entryHash) }}</code>
            </td>
          </tr>

          <tr v-if="!entries.length && !loading">
            <td colspan="7" class="text-center text-medium-emphasis py-8">
              No audit entries in this range.
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card>
  </div>
</template>

<style scoped>
.detail-cell {
  max-width: 32ch;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
