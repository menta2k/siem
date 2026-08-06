<script setup lang="ts">
import { computed } from 'vue'
import type { components } from '@/api/schema'

// Enums are inlined as string unions on the properties that use them, so both types
// are derived from VendorVerdict rather than imported as standalone schemas.
type VendorVerdict = components['schemas']['VendorVerdict']
type Vendor = NonNullable<VendorVerdict['vendor']>
type Verdict = NonNullable<VendorVerdict['verdict']>

const props = defineProps<{
  vendor?: Vendor
  verdict?: Verdict
  ruleId?: string
  score?: number
  /**
   * Set when this vendor's verdict differs from another's on the same request. The
   * badge then carries an explicit marker rather than relying on colour alone.
   */
  disagreeing?: boolean
}>()

const vendorLabel = computed(() => {
  switch (props.vendor) {
    case 'VENDOR_CLOUDFLARE':
      return 'Cloudflare'
    case 'VENDOR_F5':
      return 'F5'
    case 'VENDOR_DATADOME':
      return 'DataDome'
    default:
      return 'Unknown vendor'
  }
})

/**
 * Verdict presentation.
 *
 * `VERDICT_MONITORED` is deliberately not styled as an allow. A vendor in monitoring
 * mode did not decide to permit the request — it decided not to act — and colouring
 * the two alike would let a "everyone allowed it" reading hide a vendor that was never
 * enforcing at all.
 */
const state = computed(() => {
  switch (props.verdict) {
    case 'VERDICT_ALLOWED':
      return { label: 'Allowed', color: 'success', icon: 'mdi-check-circle-outline' }
    case 'VERDICT_BLOCKED':
      return { label: 'Blocked', color: 'error', icon: 'mdi-cancel' }
    case 'VERDICT_CHALLENGED':
      return { label: 'Challenged', color: 'warning', icon: 'mdi-help-rhombus-outline' }
    case 'VERDICT_RATE_LIMITED':
      return { label: 'Rate limited', color: 'warning', icon: 'mdi-speedometer-slow' }
    case 'VERDICT_MONITORED':
      return { label: 'Monitored', color: 'info', icon: 'mdi-eye-outline' }
    case 'VERDICT_UNKNOWN':
      return { label: 'Unknown', color: 'grey', icon: 'mdi-help-circle-outline' }
    default:
      return { label: 'Not reported', color: 'grey', icon: 'mdi-minus-circle-outline' }
  }
})

const scoreLabel = computed(() =>
  typeof props.score === 'number' ? props.score.toFixed(2) : null,
)
</script>

<template>
  <v-card
    :class="['vendor-verdict', { 'vendor-verdict--disagreeing': disagreeing }]"
    variant="outlined"
    density="compact"
  >
    <v-card-text class="py-2 px-3">
      <div class="d-flex align-center ga-2 mb-1">
        <span class="text-subtitle-2">{{ vendorLabel }}</span>
        <!--
          Disagreement is marked with an icon AND a text label, not colour alone:
          colour is the one channel a colour-blind analyst cannot rely on, and this is
          the single most decision-relevant fact on the card.
        -->
        <v-chip
          v-if="disagreeing"
          color="warning"
          size="x-small"
          variant="flat"
          aria-label="This vendor disagrees with another vendor on this request"
        >
          <v-icon icon="mdi-alert-outline" start size="x-small" />
          Disagrees
        </v-chip>
      </div>

      <v-chip :color="state.color" size="small" variant="tonal">
        <v-icon :icon="state.icon" start size="small" />
        {{ state.label }}
      </v-chip>

      <div v-if="ruleId || scoreLabel" class="mt-2 text-caption text-medium-emphasis">
        <div v-if="ruleId">
          Rule <code>{{ ruleId }}</code>
        </div>
        <div v-if="scoreLabel">Score {{ scoreLabel }}</div>
      </div>
    </v-card-text>
  </v-card>
</template>

<style scoped>
.vendor-verdict {
  min-width: 180px;
}

/*
 * A left border rather than a background wash: it survives both themes, keeps the
 * verdict chip's own colour readable, and stays visible when several cards sit
 * side by side.
 */
.vendor-verdict--disagreeing {
  border-left: 4px solid rgb(var(--v-theme-warning));
}
</style>
