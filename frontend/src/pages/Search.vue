<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import type { LocationQuery, LocationQueryRaw } from 'vue-router'
import { api, toDisplayMessage } from '@/api/client'
import { RANGE_PRESETS, useSearchStore } from '@/stores/search'
import { useAuthStore } from '@/stores/auth'
import type { components } from '@/api/schema'
import { usePreferencesStore } from '@/stores/preferences'
import EventTable from '@/components/EventTable.vue'
import SearchFilters from '@/components/SearchFilters.vue'
import AsmFindings from '@/components/AsmFindings.vue'
import WafScore from '@/components/WafScore.vue'
import PayloadViewer from '@/components/PayloadViewer.vue'

const prefs = usePreferencesStore()

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
  return `${prefs.dateTime(from)} — ${prefs.dateTime(to)}`
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
      .map(
        ([key, value]) => `${key}=${Array.isArray(value) ? value.join(',') : String(value ?? '')}`,
      )
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
                  <td>
                    <code>{{ detail.summary?.eventId }}</code>
                  </td>
                </tr>
                <tr v-if="detail.summary?.client?.asn">
                  <td class="text-medium-emphasis">Network</td>
                  <!-- The owner names the number. Absent when the published table does
                       not list the ASN, which leaves the bare number as before. -->
                  <td>
                    AS{{ detail.summary.client.asn }}
                    <span v-if="detail.summary.client.asnOwner" class="text-medium-emphasis ml-1">
                      {{ detail.summary.client.asnOwner }}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td class="text-medium-emphasis">User agent</td>
                  <!-- Rendered as text. This is the field an XSS payload arrives in. -->
                  <td>{{ detail.summary?.client?.userAgent || '—' }}</td>
                </tr>
                <!-- Only when the vendor reported one. An empty row here would read as
                     "this client has no fingerprint" rather than "this feed does not
                     send them", which are different facts. -->
                <!-- Only when the vendor scored the request. An empty row would read as
                     "this request scored nothing", and on the inverted scale that is the
                     most alarming thing it could say. -->
                <tr v-if="detail.summary?.waf">
                  <td class="text-medium-emphasis">WAF</td>
                  <td><WafScore :waf="detail.summary.waf" /></td>
                </tr>
                <tr v-if="detail.summary?.ja4">
                  <td class="text-medium-emphasis">JA4</td>
                  <td>
                    <!-- The pivot the fingerprint exists for: every correlation involving
                         this client stack, whatever address it came from. -->
                    <router-link
                      :to="{ name: 'correlated-list', query: { ja4: detail.summary.ja4 } }"
                    >
                      <code>{{ detail.summary.ja4 }}</code>
                    </router-link>
                  </td>
                </tr>
                <!-- The question an event is almost always opened with: what did the
                     OTHER vendors do with this same request. The id is the answer, but
                     nobody reads a UUID — the words are the link, and the id stays for
                     pasting. -->
                <tr v-if="detail.correlationId">
                  <td class="text-medium-emphasis">Full request</td>
                  <td>
                    <router-link :to="{ name: 'correlated', params: { id: detail.correlationId } }">
                      Every vendor that saw this request
                    </router-link>
                    <div class="text-caption text-medium-emphasis">
                      <code>{{ detail.correlationId }}</code>
                    </div>
                  </td>
                </tr>

                <!-- No record found, but the ray still identifies the request across
                     vendors. A search is a worse answer than a link and a much better one
                     than a dead end — the correlation may simply be younger than this
                     event, since the join waits for the window to close. -->
                <tr v-else-if="detail.summary?.vendorRequestId">
                  <td class="text-medium-emphasis">Full request</td>
                  <td>
                    <router-link
                      :to="{
                        name: 'correlated-list',
                        query: { ray: detail.summary.vendorRequestId },
                      }"
                    >
                      Look for this request across vendors
                    </router-link>
                    <div class="text-caption text-medium-emphasis">
                      no correlated record yet — nothing has joined this event
                    </div>
                  </td>
                </tr>
              </tbody>
            </v-table>

            <!-- Above the raw payload on purpose: this is the answer to the question the
                 analyst opened the event with, and the payload is the evidence behind it.
                 Present only for F5 events that actually tripped something. -->
            <AsmFindings v-if="detail.asm" :findings="detail.asm" />

            <div class="text-subtitle-2 mb-1">Raw vendor payload</div>
            <!--
              Rendered as FIELDS, with the received bytes one click away. Every value is
              interpolated, never v-html: a payload containing markup shows as the
              characters the vendor sent, which is the whole point of keeping the raw
              record (FR-005). Structuring does not change that — parsing builds data and
              evaluates nothing.
            -->
            <PayloadViewer :raw="detail.rawPayload" :content-type="detail.rawContentType" />
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
