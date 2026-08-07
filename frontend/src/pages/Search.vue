<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'
import { RANGE_PRESETS, useSearchStore } from '@/stores/search'
import { useAuthStore } from '@/stores/auth'
import type { components } from '@/api/schema'
import EventTable from '@/components/EventTable.vue'
import SearchFilters from '@/components/SearchFilters.vue'

type EventSummary = components['schemas']['EventSummary']
type EventDetail = components['schemas']['EventDetail']

const route = useRoute()
const router = useRouter()
const store = useSearchStore()
const auth = useAuthStore()

const detail = ref<EventDetail | null>(null)
const detailOpen = ref(false)
const detailError = ref('')
const exporting = ref(false)
const exportNotice = ref('')

/**
 * The range control is REQUIRED and pre-filled.
 *
 * An unbounded query is not expressible in this UI. That is deliberate: the backend
 * rejects one, and offering a control that produces a guaranteed error teaches
 * analysts that the tool is broken rather than that their query was.
 */
const rangeLabel = computed(() => {
  const from = new Date(store.from)
  const to = new Date(store.to)
  return `${from.toLocaleString()} — ${to.toLocaleString()}`
})

function applyPreset(minutes: number): void {
  store.setRangePreset(minutes)
  void runSearch()
}

/**
 * Reflects the search into the URL, which is what runs it.
 *
 * Deliberately does NOT call store.search() as well. Rewriting the query fires the
 * watcher below, so doing both sent two identical requests for every submission and the
 * results of the second appended to the first — one matching event rendered as two rows.
 * The URL is the source of truth for a search; the single path through it is what keeps a
 * pasted link and a clicked button behaving identically.
 */
async function runSearch(): Promise<void> {
  const query = store.toQuery()
  // Navigating to the location already shown is a duplicate navigation: the watcher
  // never fires, so pressing Search again with nothing changed would do nothing at all.
  // Re-running directly is the one case that must bypass the URL.
  if (sameQuery(query, route.query)) {
    await store.search()
    return
  }
  await router.replace({ name: 'search', query })
}

/** Compares two query objects by their serialised pairs. */
function sameQuery(a: LocationQueryRaw, b: LocationQuery): boolean {
  const flatten = (query: LocationQueryRaw | LocationQuery): string =>
    Object.entries(query)
      .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : String(value ?? '')}`)
      .sort()
      .join('&')
  return flatten(a) === flatten(b)
}

onMounted(async () => {
  store.fromQuery(route.query)
  await store.search()
})

// A pasted link must produce the search it encodes, including when the user navigates
// back to a previous search within the app.
watch(
  () => route.query,
  (query) => {
    store.fromQuery(query)
    void store.search()
  },
)

async function openDetail(item: EventSummary): Promise<void> {
  detailOpen.value = true
  detail.value = null
  detailError.value = ''
  try {
    const { data } = await api.GET('/api/v1/events/{eventId}', {
      params: { path: { eventId: item.eventId ?? '' } },
    })
    detail.value = data ?? null
  } catch (err) {
    detailError.value = toDisplayMessage(err)
  }
}

async function runExport(format: 'EXPORT_FORMAT_NDJSON' | 'EXPORT_FORMAT_CSV'): Promise<void> {
  exporting.value = true
  exportNotice.value = ''
  try {
    const { data } = await api.POST('/api/v1/search/export', {
      body: {
        timeRange: { from: store.from, to: store.to },
        filters: store.filters,
        format,
      },
    })
    if (!data) return

    downloadExport(data.content ?? '', data.contentType ?? '', data.filename ?? 'export')
    exportNotice.value = data.truncated
      ? `Exported ${data.rowCount} rows — the row cap was reached, so this file is a prefix of the result.`
      : `Exported ${data.rowCount} rows.`
  } catch (err) {
    exportNotice.value = toDisplayMessage(err)
  } finally {
    exporting.value = false
  }
}

/**
 * Saves the export to a file.
 *
 * The content arrives base64-encoded because the field is proto `bytes`. It is written
 * to a Blob and never inserted into the DOM — the file contains attacker-controlled log
 * text, and the only safe thing to do with it is hand it to the browser as an opaque
 * download.
 */
function downloadExport(base64: string, contentType: string, filename: string): void {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)

  const url = URL.createObjectURL(new Blob([bytes], { type: contentType }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename

  // The anchor has to be IN the document. Chromium ignores a click on a detached
  // element, so a download built this way silently does nothing — no error, no file,
  // and the user concludes the export is broken.
  link.style.display = 'none'
  document.body.appendChild(link)
  link.click()
  link.remove()

  URL.revokeObjectURL(url)
}
</script>

<template>
  <div>
    <v-alert v-if="store.errorMessage" type="error" variant="tonal" class="mb-4" closable>
      {{ store.errorMessage }}
    </v-alert>

    <v-alert v-if="exportNotice" type="info" variant="tonal" class="mb-4" closable>
      {{ exportNotice }}
    </v-alert>

    <v-row>
      <v-col cols="12" md="3">
        <SearchFilters
          :model-value="store.filters"
          @update:model-value="store.setFilters"
          @apply="runSearch"
        />
      </v-col>

      <v-col cols="12" md="9">
        <v-card class="mb-4">
          <v-card-text class="d-flex flex-wrap align-center ga-2">
            <v-icon icon="mdi-clock-outline" size="small" />
            <span class="text-body-2 mr-2">{{ rangeLabel }}</span>

            <v-btn
              v-for="preset in RANGE_PRESETS"
              :key="preset.minutes"
              size="small"
              variant="tonal"
              @click="applyPreset(preset.minutes)"
            >
              {{ preset.label }}
            </v-btn>

            <v-spacer />

            <v-menu v-if="auth.can.export">
              <template #activator="{ props: menuProps }">
                <v-btn
                  v-bind="menuProps"
                  variant="text"
                  size="small"
                  :loading="exporting"
                  prepend-icon="mdi-download"
                >
                  Export
                </v-btn>
              </template>
              <v-list density="compact">
                <v-list-item title="NDJSON" @click="runExport('EXPORT_FORMAT_NDJSON')" />
                <v-list-item title="CSV" @click="runExport('EXPORT_FORMAT_CSV')" />
              </v-list>
            </v-menu>
          </v-card-text>
        </v-card>

        <v-card>
          <v-card-text>
            <EventTable
              :items="store.items"
              :loading="store.loading"
              :has-more="store.hasMore"
              :total="store.total"
              :total-is-estimate="store.totalIsEstimate"
              @load-more="store.loadMore"
              @select="openDetail"
            />
          </v-card-text>
        </v-card>
      </v-col>
    </v-row>

    <v-dialog v-model="detailOpen" max-width="900">
      <v-card>
        <v-card-title class="text-subtitle-1">Event detail</v-card-title>
        <v-card-text>
          <v-alert v-if="detailError" type="error" variant="tonal" class="mb-3">
            {{ detailError }}
          </v-alert>

          <div v-else-if="!detail" class="text-body-2 text-medium-emphasis">Loading…</div>

          <template v-else>
            <v-table density="compact" class="mb-4">
              <tbody>
                <tr>
                  <td class="text-medium-emphasis">Event</td>
                  <td><code>{{ detail.summary?.eventId }}</code></td>
                </tr>
                <tr>
                  <td class="text-medium-emphasis">User agent</td>
                  <!-- Rendered as text. This is the field an XSS payload arrives in. -->
                  <td>{{ detail.summary?.client?.userAgent || '—' }}</td>
                </tr>
                <tr v-if="detail.correlationId">
                  <td class="text-medium-emphasis">Correlated</td>
                  <td>
                    <router-link :to="{ name: 'correlated', params: { id: detail.correlationId } }">
                      {{ detail.correlationId }}
                    </router-link>
                  </td>
                </tr>
              </tbody>
            </v-table>

            <div class="text-subtitle-2 mb-1">Raw vendor payload</div>
            <!--
              The payload is shown verbatim in a <pre> as TEXT. Vue escapes it, so a
              payload containing markup renders as the characters the vendor sent —
              which is the whole point of keeping the raw record (FR-005).
            -->
            <pre class="raw-payload">{{ detail.rawPayload || '(not retained)' }}</pre>
          </template>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="detailOpen = false">Close</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<style scoped>
.raw-payload {
  max-height: 40vh;
  overflow: auto;
  padding: 0.75rem;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.05);
  font-size: 0.8rem;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
