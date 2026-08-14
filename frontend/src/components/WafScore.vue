<script setup lang="ts">
import { computed } from 'vue'
import type { components } from '@/api/schema'

type WafDetail = components['schemas']['WafDetail']

/**
 * The WAF's own view of a request.
 *
 * THE SCALE IS INVERTED and this component exists largely to stop that being misread.
 * Cloudflare scores 1-100 where **1 is certainly an attack** and 100 is certainly clean
 * — the opposite direction to every other score in the console, where higher means
 * worse. Showing the bare number invites exactly the wrong reading, so the score is
 * always rendered with a word beside it.
 *
 * 1-100, not the 1-99 Cloudflare documents: it sends 100 for a definitively clean
 * request, and that is the most common value in real traffic.
 */
const props = defineProps<{ waf: WafDetail }>()

/** 0 is not a score. It means the request was never scored. */
const scored = computed(() => (props.waf.attackScore ?? 0) > 0)

/**
 * Bands, on the inverted scale. The boundaries follow how the scores actually fall in
 * production: real detections land at 1-4, the noisy rules sit at 85-89, and untouched
 * traffic scores 100 — so the middle bands are wide enough that nothing lands in them
 * by accident.
 */
const band = computed(() => {
  const score = props.waf.attackScore ?? 0
  if (score <= 20) return { label: 'attack', color: 'error' }
  if (score <= 50) return { label: 'suspicious', color: 'warning' }
  if (score <= 80) return { label: 'leaning clean', color: 'info' }
  return { label: 'clean', color: 'success' }
})

/**
 * The sub-scores worth showing: only those that are themselves in attack territory.
 *
 * The overall score is driven by whichever class fired, so listing all three on every
 * request buries the one that matters — a SQLi detection reads 4 for SQLi and 98 for
 * XSS and RCE, and the 98s are noise.
 */
const drivers = computed(() =>
  [
    { label: 'SQLi', score: props.waf.sqliScore ?? 0 },
    { label: 'XSS', score: props.waf.xssScore ?? 0 },
    { label: 'RCE', score: props.waf.rceScore ?? 0 },
  ].filter((d) => d.score > 0 && d.score <= 50),
)

/**
 * `log` is the one action worth calling out: the rule matched and was deliberately not
 * enforced, which is the state ruleset tuning acts on.
 */
const actionColor = computed(() => {
  switch ((props.waf.action ?? '').toLowerCase()) {
    case 'log':
      return 'warning'
    case 'block':
    case 'drop':
      return 'error'
    case 'skip':
    case 'bypass':
      return 'info'
    default:
      return 'default'
  }
})
</script>

<template>
  <div class="d-flex align-center flex-wrap ga-2">
    <!-- The number never travels alone. "2" means attack and "86" means clean, which is
         backwards from every other score on this screen. -->
    <v-chip v-if="scored" :color="band.color" size="x-small" variant="tonal">
      {{ waf.attackScore }}/100 {{ band.label }}
    </v-chip>

    <v-chip v-if="waf.action" :color="actionColor" size="x-small" variant="tonal">
      {{ waf.action }}
    </v-chip>

    <span v-if="waf.source" class="text-caption text-medium-emphasis">
      {{ waf.source }}
    </span>

    <span v-for="d in drivers" :key="d.label" class="text-caption text-error">
      {{ d.label }} {{ d.score }}
    </span>
  </div>
</template>
