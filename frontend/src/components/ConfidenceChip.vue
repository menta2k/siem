<script setup lang="ts">
import { computed } from 'vue'
import type { components } from '@/api/schema'

// The generator inlines enums as string unions on the properties that use them
// rather than emitting standalone schemas, so the type is derived from a field.
type Confidence = NonNullable<components['schemas']['CorrelatedRequest']['confidence']>

const props = defineProps<{
  confidence?: Confidence
  /** 1 = exact shared request id, 2 = heuristic match. */
  joinTier?: number
  /**
   * Above 1, several events competed for the join and the chosen one may be wrong.
   *
   * Only meaningful on a HEURISTIC join — see competingCandidates below.
   */
  candidateCount?: number
  /** True when the client address looks like NAT, a proxy, or a carrier range. */
  ipShared?: boolean
  vendorCount?: number
}>()

/**
 * Whether events genuinely competed to be this request's partner.
 *
 * An EXACT join rests on an identifier every member carries, so nothing competed —
 * the members are one request however many of them there are. A Worker-protected
 * request legitimately produces two Cloudflare rows, the client-facing request and the
 * fetch to the origin, and reading that as two candidates for one slot warned that the
 * partner "may be the wrong one" on 95.8% of exact joins.
 *
 * The tier is checked here as well as in the correlator so records written before that
 * fix stop showing the warning immediately, rather than only once they age out.
 */
const competingCandidates = computed(
  () => props.joinTier !== 1 && (props.candidateCount ?? 1) > 1,
)

/**
 * The chip states, ordered by how much the reader should hesitate.
 *
 * A low-confidence join is shown as a join that MIGHT be wrong, never hidden and never
 * dressed up as certain. Suppressing it loses a correlation the analyst probably
 * wanted; presenting it as fact teaches them to trust joins that have not earned it,
 * which is the more expensive of the two mistakes.
 */
const state = computed(() => {
  // A single-vendor record involved no join, so "confidence" would be answering a
  // question nobody asked. Saying so plainly beats a green tick that implies
  // corroboration which does not exist.
  if ((props.vendorCount ?? 0) <= 1) {
    return {
      label: 'Single vendor',
      color: 'grey',
      icon: 'mdi-numeric-1-circle-outline',
      variant: 'tonal' as const,
    }
  }

  switch (props.confidence) {
    case 'CONFIDENCE_HIGH':
      return { label: 'High', color: 'success', icon: 'mdi-shield-check', variant: 'tonal' as const }
    case 'CONFIDENCE_MEDIUM':
      return { label: 'Medium', color: 'info', icon: 'mdi-shield-half-full', variant: 'tonal' as const }
    case 'CONFIDENCE_LOW':
      // Outlined rather than tonal: a low-confidence join should not sit at the same
      // visual weight as a certain one.
      return {
        label: 'Low',
        color: 'warning',
        icon: 'mdi-shield-alert-outline',
        variant: 'outlined' as const,
      }
    default:
      return {
        label: 'Unknown',
        color: 'grey',
        icon: 'mdi-help-circle-outline',
        variant: 'outlined' as const,
      }
  }
})

/** Why the platform reached this confidence, in the analyst's terms. */
const explanation = computed(() => {
  if ((props.vendorCount ?? 0) <= 1) {
    return 'Only one vendor reported this request, so nothing was joined. This is normal for hostnames behind a single vendor.'
  }

  const reasons: string[] = []
  if (props.joinTier === 1) {
    reasons.push('The vendors reported the same request identifier, so the match is exact.')
  } else if (props.joinTier === 2) {
    reasons.push(
      'Matched on client address, host, path and method within the correlation window.',
    )
  }
  if (props.ipShared) {
    reasons.push(
      'The client address is shared (NAT, proxy, or carrier range), so several clients could produce this same match.',
    )
  }
  if (competingCandidates.value) {
    reasons.push(
      `${props.candidateCount} events from one vendor competed for this join, so the chosen partner may be the wrong one.`,
    )
  }
  return reasons.join(' ')
})
</script>

<template>
  <v-tooltip :text="explanation" location="top" max-width="380">
    <template #activator="{ props: tooltipProps }">
      <v-chip
        v-bind="tooltipProps"
        :color="state.color"
        :variant="state.variant"
        size="small"
        :aria-label="`Join confidence: ${state.label}. ${explanation}`"
      >
        <v-icon :icon="state.icon" start size="small" />
        {{ state.label }}
      </v-chip>
    </template>
  </v-tooltip>
</template>
