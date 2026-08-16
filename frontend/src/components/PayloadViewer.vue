<script setup lang="ts">
/**
 * Shows a raw vendor payload as fields, with the received bytes one click away.
 *
 * Two things an analyst does with a payload, and the old `<pre>` supported neither: find
 * one field among fifty, and read a value that is itself a document. So the fields are
 * filterable, the padding folds away, and the raw text stays reachable — because the
 * formatted view is an interpretation, and evidence has to be checkable against what the
 * vendor actually sent.
 *
 * Every value is interpolated, never v-html. This is attacker-controlled text: a payload
 * carrying markup renders as the characters the vendor sent, which is the entire reason
 * the raw record is kept.
 */
import { computed, ref } from 'vue'
import { structurePayload } from '@/lib/payload-structure'
import type { PayloadField } from '@/lib/payload-structure'
import { copyText } from '@/lib/clipboard'

const props = withDefaults(
  defineProps<{
    raw?: string | null
    /** The vendor's own name for the encoding, shown so the reading is attributable. */
    contentType?: string | null
    /** Starts collapsed inside a list, where several of these share one page. */
    dense?: boolean
  }>(),
  { raw: '', contentType: '', dense: false },
)

const structured = computed(() => structurePayload(props.raw))

const filter = ref('')
const showEmpty = ref(false)
const showRaw = ref(false)
const copied = ref(false)

/**
 * The fields actually rendered.
 *
 * Empty fields are hidden by DEFAULT and counted, never dropped silently. Two thirds of
 * an F5 record is `N/A`, and a viewer that quietly discards fields is one an analyst
 * cannot trust to be showing them everything.
 */
const visible = computed<PayloadField[]>(() => {
  const needle = filter.value.trim().toLowerCase()
  return structured.value.fields.filter((field) => {
    if (!showEmpty.value && field.kind === 'empty') return false
    if (!needle) return true
    return field.path.toLowerCase().includes(needle) || field.value.toLowerCase().includes(needle)
  })
})

/** Describes what is on screen, including what was folded away. */
const summary = computed(() => {
  const { shape, fields, emptyCount } = structured.value
  if (shape === 'text') return props.contentType || 'as received'

  const kind = shape === 'json' ? 'JSON' : 'key/value'
  const shown = visible.value.length
  const parts = [`${kind} · ${shown} of ${fields.length} fields`]
  if (!showEmpty.value && emptyCount > 0) parts.push(`${emptyCount} empty hidden`)
  return parts.join(' · ')
})

async function copyRaw(): Promise<void> {
  copied.value = await copyText(structured.value.raw)
  // Reverts on its own: a button stuck reading "Copied" says nothing about the NEXT copy.
  if (copied.value) setTimeout(() => (copied.value = false), 2000)
}
</script>

<template>
  <div :class="{ dense: props.dense }">
    <div class="d-flex align-center flex-wrap ga-2 mb-2">
      <div class="text-caption text-medium-emphasis">{{ summary }}</div>

      <v-spacer />

      <v-text-field
        v-if="structured.shape !== 'text' && !showRaw"
        v-model="filter"
        density="compact"
        variant="outlined"
        hide-details
        clearable
        placeholder="Filter fields"
        prepend-inner-icon="mdi-magnify"
        class="payload-filter"
      />

      <v-btn
        v-if="structured.shape !== 'text' && !showRaw && structured.emptyCount > 0"
        size="x-small"
        variant="text"
        @click="showEmpty = !showEmpty"
      >
        {{ showEmpty ? 'Hide' : 'Show' }} empty
      </v-btn>

      <v-btn
        v-if="structured.shape !== 'text'"
        size="x-small"
        variant="text"
        @click="showRaw = !showRaw"
      >
        {{ showRaw ? 'Fields' : 'Raw' }}
      </v-btn>

      <v-btn
        v-if="structured.raw"
        size="x-small"
        variant="text"
        :prepend-icon="copied ? 'mdi-check' : 'mdi-content-copy'"
        @click="copyRaw"
      >
        {{ copied ? 'Copied' : 'Copy' }}
      </v-btn>
    </div>

    <!-- Nothing was retained. Said plainly: an empty box reads as a bug. -->
    <div v-if="!structured.raw" class="text-body-2 text-medium-emphasis">(not retained)</div>

    <!-- Either the payload has no structure to show, or the analyst asked for the bytes. -->
    <pre v-else-if="showRaw || structured.shape === 'text'" class="payload-raw">{{
      structured.raw
    }}</pre>

    <template v-else>
      <!-- The delivery envelope, kept apart from the record it carried. A relay's clock
           and the appliance's are different facts and are read as one when they share a
           table. -->
      <div v-if="structured.envelope.length" class="envelope mb-2">
        <span v-for="item in structured.envelope" :key="item.path" class="envelope-item">
          <span class="text-medium-emphasis">{{ item.path }}</span>
          <span class="ml-1">{{ item.value }}</span>
        </span>
      </div>

      <div v-if="visible.length === 0" class="text-body-2 text-medium-emphasis py-2">
        No field matches “{{ filter }}”.
      </div>

      <div v-else class="payload-fields">
        <div v-for="field in visible" :key="field.path" class="payload-row">
          <div class="payload-key text-medium-emphasis">{{ field.path }}</div>

          <div class="payload-value">
            <!-- A set the vendor packed into one comma-separated value. Three violations
                 are three findings, not one sentence. -->
            <template v-if="field.kind === 'list'">
              <v-chip
                v-for="item in field.items"
                :key="item"
                size="x-small"
                variant="tonal"
                class="mr-1 mb-1"
              >
                {{ item }}
              </v-chip>
            </template>

            <!-- A document inside a field: an escaped HTTP request, or nested JSON.
                 Rendered as its own block so headers land where headers go. -->
            <pre
              v-else-if="field.kind === 'block' || field.kind === 'json'"
              class="payload-block"
              >{{ field.value }}</pre>

            <span v-else-if="field.kind === 'empty'" class="text-disabled">{{
              field.value || '—'
            }}</span>

            <span v-else>{{ field.value }}</span>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.payload-filter {
  max-width: 14rem;
}

.payload-fields {
  max-height: 40vh;
  overflow: auto;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.04);
}

/* A grid, not a table: the key column stays aligned down the whole record while a value
   holding an HTTP request is free to be twenty lines tall. */
.payload-row {
  display: grid;
  grid-template-columns: minmax(9rem, 14rem) 1fr;
  gap: 0.75rem;
  padding: 0.3rem 0.6rem;
  border-bottom: 1px solid rgba(var(--v-theme-on-surface), 0.06);
}

.payload-row:last-child {
  border-bottom: none;
}

.payload-key,
.payload-value {
  font-family: monospace;
  font-size: 0.75rem;
  overflow-wrap: anywhere;
}

.payload-block {
  margin: 0;
  padding: 0.4rem 0.5rem;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.06);
  font-size: 0.72rem;
  /* Wraps rather than scrolling sideways: a header line that runs off the edge is a
     header line nobody reads. */
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  max-height: 22rem;
  overflow-y: auto;
}

.envelope {
  font-size: 0.72rem;
  font-family: monospace;
}

.envelope-item:not(:last-child)::after {
  content: '·';
  margin: 0 0.4rem;
  opacity: 0.5;
}

.payload-raw {
  max-height: 40vh;
  overflow: auto;
  padding: 0.75rem;
  border-radius: 4px;
  background: rgba(var(--v-theme-on-surface), 0.05);
  font-family: monospace;
  font-size: 0.75rem;
  white-space: pre-wrap;
  word-break: break-all;
}

/* On a page that stacks several of these, the payload is supporting evidence and must
   not out-scroll the thing it supports. */
.dense .payload-fields {
  max-height: 18rem;
}
</style>
