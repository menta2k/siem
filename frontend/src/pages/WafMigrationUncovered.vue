<script setup lang="ts">
/**
 * Stage 1: what F5 blocks and Cloudflare does not see.
 *
 * These are the holes. Each row is one F5 violation on one host and method — the unit a
 * single Cloudflare rule gets written for — and the drill-down is the requests that
 * would have to match it. Nothing here writes a rule: it says what a rule has to catch,
 * and the writing belongs to whoever owns the site.
 */
import { computed, onMounted, ref } from 'vue'
import { api, toDisplayMessage } from '@/api/client'
import type { components } from '@/api/schema'
import { usePreferencesStore } from '@/stores/preferences'
import { useMigrationRange } from '@/composables/useMigrationRange'
import MigrationStageHeader from '@/components/MigrationStageHeader.vue'
import MigrationSamples from '@/components/MigrationSamples.vue'

type UncoveredGroup = components['schemas']['WafUncoveredGroup']

const prefs = usePreferencesStore()
const { rangeHours, host, currentRange, queryParams } = useMigrationRange()

const groups = ref<UncoveredGroup[]>([])
const loading = ref(false)
const errorMessage = ref('')
const expanded = ref<string | null>(null)
const range = ref(currentRange())

function rowKey(g: UncoveredGroup): string {
  return `${g.violation}|${g.requestHost}|${g.requestMethod}`
}

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  expanded.value = null
  // Frozen for the page: the samples a row opens must come from the same window the
  // counts did, and recomputing "now" per request would drift them apart.
  range.value = currentRange()

  try {
    const { data } = await api.GET('/api/v1/waf-migration/uncovered', {
      params: { query: queryParams() },
    })
    groups.value = data?.groups ?? []
  } catch (err) {
    errorMessage.value = toDisplayMessage(err)
  } finally {
    loading.value = false
  }
}

onMounted(load)

function toggle(g: UncoveredGroup): void {
  expanded.value = expanded.value === rowKey(g) ? null : rowKey(g)
}

const totalRequests = computed(() =>
  groups.value.reduce((sum, g) => sum + Number(g.requests ?? 0), 0),
)

/**
 * A group where a Cloudflare rule matched and let the request through anyway.
 *
 * This needs the OPPOSITE fix from the rest of the stage. An exemption is already in
 * place at the edge, so adding a detection rule behind it changes nothing — the
 * exemption has to be narrowed first. Worth its own marker rather than a column nobody
 * reads.
 */
function allowlistShare(g: UncoveredGroup): number {
  const requests = Number(g.requests ?? 0)
  if (!requests) return 0
  return Number(g.cloudflareAllowlisted ?? 0) / requests
}
</script>

<template>
  <div>
    <MigrationStageHeader
      :step="1"
      title="Blocked by F5, invisible to Cloudflare"
      definition="F5 blocked the request and no Cloudflare rule matched it at all. Cloudflare has nothing that covers this traffic."
      action="Write a Cloudflare rule for each row, and deploy it in log mode. It will appear in step 2 once it starts matching."
      :range-hours="rangeHours"
      :host="host"
      :loading="loading"
      @update:range-hours="rangeHours = $event"
      @update:host="host = $event"
      @reload="load"
    />

    <v-alert v-if="errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ errorMessage }}
    </v-alert>

    <v-card>
      <v-card-text>
        <div v-if="loading" class="d-flex align-center ga-3 py-4">
          <v-progress-circular indeterminate size="20" />
          <span class="text-body-2 text-medium-emphasis">Reading correlated records…</span>
        </div>

        <!-- Not an empty table. "Nothing here" is a RESULT in this stage — it means
             Cloudflare already sees everything F5 blocks — and it should read as one. -->
        <div v-else-if="groups.length === 0" class="py-6 text-center">
          <v-icon icon="mdi-shield-check" size="32" class="text-success mb-2" />
          <div class="text-body-1">Nothing uncovered in this window.</div>
          <div class="text-body-2 text-medium-emphasis">
            Every request F5 blocked was also matched by a Cloudflare rule.
          </div>
        </div>

        <template v-else>
          <div class="text-caption text-medium-emphasis mb-2">
            {{ groups.length }} groups · {{ totalRequests.toLocaleString() }} requests F5 blocked
            that Cloudflare did not act on
          </div>

          <v-table density="compact">
            <thead>
              <tr>
                <th>F5 violation</th>
                <th>Host</th>
                <th>Method</th>
                <th class="text-right">Requests</th>
                <th class="text-right">Paths</th>
                <th class="text-right">Clients</th>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              <template v-for="g in groups" :key="rowKey(g)">
                <tr class="row-clickable" @click="toggle(g)">
                  <td>
                    <div>{{ g.violation }}</div>
                    <!-- The case that needs the opposite fix, marked where it is read. -->
                    <v-chip
                      v-if="allowlistShare(g) > 0"
                      size="x-small"
                      color="warning"
                      variant="tonal"
                      class="mt-1"
                    >
                      {{ g.cloudflareAllowlisted }} allowed by a CF rule
                    </v-chip>
                  </td>
                  <td class="text-caption">{{ g.requestHost }}</td>
                  <td class="text-caption">{{ g.requestMethod }}</td>
                  <td class="text-right">{{ Number(g.requests ?? 0).toLocaleString() }}</td>
                  <!-- Breadth separates a broken client from someone walking the site,
                       which are the same count and completely different rules. -->
                  <td class="text-right text-medium-emphasis">{{ g.paths }}</td>
                  <td class="text-right text-medium-emphasis">{{ g.clients }}</td>
                  <td class="text-caption text-no-wrap">{{ prefs.dateTime(g.lastSeen) }}</td>
                  <td class="text-right">
                    <v-icon
                      :icon="expanded === rowKey(g) ? 'mdi-chevron-up' : 'mdi-chevron-down'"
                      size="small"
                    />
                  </td>
                </tr>
                <tr v-if="expanded === rowKey(g)">
                  <td colspan="8" class="pa-0">
                    <MigrationSamples
                      :range="range"
                      :violation="g.violation"
                      :request-host="g.requestHost"
                      :request-method="g.requestMethod"
                      f5-verdict="blocked"
                      cloudflare-verdict="allowed"
                    />
                  </td>
                </tr>
              </template>
            </tbody>
          </v-table>
        </template>
      </v-card-text>
    </v-card>
  </div>
</template>

<style scoped>
.row-clickable {
  cursor: pointer;
}
</style>
