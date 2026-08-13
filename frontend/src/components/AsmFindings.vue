<script setup lang="ts">
import { computed } from 'vue'
import type { components } from '@/api/schema'

type Findings = components['schemas']['AsmFindings']

/**
 * Explains a BIG-IP block in terms an analyst can act on.
 *
 * A raw ASM record says "Illegal file type" and "200004165" and stops there, so deciding
 * whether that is an attack or a false positive meant leaving the console for the BIG-IP
 * UI. This is the same information with its meanings attached: what each check is for,
 * what an attacker gains if it is real, and how likely the signature is to be wrong.
 */
const props = defineProps<{ findings: Findings }>()

const violations = computed(() => props.findings.violations ?? [])
const signatures = computed(() => props.findings.signatures ?? [])

/**
 * ASM's severity vocabulary, mapped onto the palette already used for verdicts.
 *
 * Anything unrecognised falls through to a neutral chip rather than to a colour that
 * would assert a severity the appliance did not report.
 */
function severityColor(severity: string | undefined): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'error'
    case 'error':
      return 'warning'
    case 'warning':
      return 'warning'
    case 'notice':
    case 'informational':
      return 'info'
    default:
      return 'default'
  }
}

/**
 * Accuracy is the false-positive likelihood, so the scale is INVERTED against risk:
 * "low" accuracy is the alarming one because it means the signature often fires on
 * benign traffic. Colouring it like a low risk would invert the meaning.
 */
function accuracyColor(accuracy: string | undefined): string {
  switch (accuracy?.toLowerCase()) {
    case 'high':
      return 'success'
    case 'medium':
      return 'warning'
    case 'low':
      return 'error'
    default:
      return 'default'
  }
}

function riskColor(risk: string | undefined): string {
  switch (risk?.toLowerCase()) {
    case 'high':
      return 'error'
    case 'medium':
      return 'warning'
    case 'low':
      return 'info'
    default:
      return 'default'
  }
}

/**
 * BIG-IP writes its long descriptions as "Summary:\n...\n\nImpact:\n..." blocks. The
 * first section is the one worth showing without a click; the rest is reference material
 * behind the expander.
 */
function summaryOf(description: string | undefined): string {
  if (!description) return ''
  const body = description.replace(/^Summary:\s*/i, '')
  const [first] = body.split(/\n\s*\n/)
  return (first ?? '').trim()
}

function hasMoreThanSummary(description: string | undefined): boolean {
  if (!description) return false
  return summaryOf(description).length < description.replace(/^Summary:\s*/i, '').trim().length
}
</script>

<template>
  <div class="mb-4">
    <div class="d-flex align-center mb-2">
      <div class="text-subtitle-2">Why BIG-IP flagged this</div>
      <v-chip
        v-if="findings.violationRating"
        size="x-small"
        variant="tonal"
        color="warning"
        class="ml-2"
      >
        threat rating {{ findings.violationRating }}/5
      </v-chip>
    </div>

    <!-- The key facts are ALWAYS VISIBLE. An accordion looks tidier and costs a click
         per violation to learn anything, which on a six-violation block is six clicks
         before the analyst knows whether it matters. Only the long vendor prose is
         folded away. -->
    <div v-if="violations.length" class="mb-3">
      <div v-for="(v, i) in violations" :key="`v${i}`" class="asm-item pa-2 mb-2 rounded">
        <div class="d-flex align-center flex-wrap ga-2">
          <v-chip :color="severityColor(v.severity)" size="x-small" variant="tonal">
            {{ v.severity || 'unrated' }}
          </v-chip>
          <!-- Interpolated, never v-html. -->
          <span class="text-body-2 font-weight-medium">{{ v.title }}</span>
          <span v-if="v.attackType" class="text-caption text-medium-emphasis">
            {{ v.attackType }}
          </span>
          <!-- The VIOL_* constant is what BIG-IP documentation and support cases use,
               even though the logs never carry it. -->
          <code v-if="v.name" class="text-caption text-medium-emphasis">{{ v.name }}</code>
        </div>

        <div v-if="v.risk" class="text-body-2 mt-1">{{ v.risk }}</div>
        <div v-if="!v.name" class="text-caption text-medium-emphasis mt-1">
          Not in the bundled ASM catalogue — regenerate it from the appliance for the description.
        </div>

        <details v-if="v.description || v.examples" class="mt-1">
          <summary class="text-caption text-medium-emphasis asm-more">What the check does</summary>
          <div v-if="v.description" class="text-body-2 text-pre-wrap mt-1">
            {{ v.description }}
          </div>
          <div v-if="v.examples" class="text-body-2 text-pre-wrap mt-1">
            <span class="text-caption font-weight-medium">Examples: </span>{{ v.examples }}
          </div>
        </details>
      </div>
    </div>

    <div v-if="signatures.length">
      <div class="text-caption text-medium-emphasis mb-1">
        Attack signatures ({{ signatures.length }})
      </div>
      <div v-for="s in signatures" :key="s.id" class="asm-item pa-2 mb-2 rounded">
        <div class="d-flex align-center flex-wrap ga-2">
          <code class="text-caption">{{ s.id }}</code>
          <span class="text-body-2 font-weight-medium">{{ s.name || 'Unknown signature' }}</span>
          <v-chip v-if="s.risk" :color="riskColor(s.risk)" size="x-small" variant="tonal">
            risk {{ s.risk }}
          </v-chip>
          <!-- Accuracy is the false-positive likelihood, which is why a LOW value is the
               one coloured as a problem. -->
          <v-chip
            v-if="s.accuracy"
            :color="accuracyColor(s.accuracy)"
            size="x-small"
            variant="tonal"
          >
            accuracy {{ s.accuracy }}
          </v-chip>
          <v-chip v-if="s.userDefined" size="x-small" variant="tonal" color="info">custom</v-chip>
          <span v-if="s.attackType" class="text-caption text-medium-emphasis">
            {{ s.attackType }}
          </span>
        </div>

        <div v-if="!s.name" class="text-caption text-medium-emphasis mt-1">
          Not in the bundled ASM catalogue — regenerate it from the appliance for the description.
        </div>

        <!-- The pivot into every other tool the analyst owns, so it is never folded
             away. Rendered as text rather than links: the value comes from a vendor
             dump, and a CVE id is trivially copied. -->
        <div v-if="s.cves?.length" class="d-flex flex-wrap ga-1 mt-1">
          <v-chip v-for="cve in s.cves" :key="cve" size="x-small" variant="outlined">
            {{ cve }}
          </v-chip>
        </div>

        <div v-if="s.description" class="text-body-2 mt-1">{{ summaryOf(s.description) }}</div>

        <details v-if="hasMoreThanSummary(s.description)" class="mt-1">
          <summary class="text-caption text-medium-emphasis asm-more">Full signature notes</summary>
          <div class="text-body-2 text-pre-wrap mt-1">{{ s.description }}</div>
        </details>

        <div v-if="s.references?.length" class="mt-1">
          <div v-for="ref in s.references" :key="ref" class="text-caption text-break">
            {{ ref }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.text-pre-wrap {
  white-space: pre-wrap;
}
/* A hairline rather than a card: these stack several deep on a real block, and a card
   each turns one finding into a wall of elevation. */
.asm-item {
  border: 1px solid rgba(var(--v-border-color), var(--v-border-opacity));
}
.asm-more {
  cursor: pointer;
}
</style>
