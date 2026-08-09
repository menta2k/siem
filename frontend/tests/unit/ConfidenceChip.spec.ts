import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'
import ConfidenceChip from '@/components/ConfidenceChip.vue'

const vuetify = createVuetify({
  components: vuetifyComponents,
  directives: vuetifyDirectives,
})

function render(props: Record<string, unknown>) {
  return mount(ConfidenceChip, {
    props,
    global: { plugins: [vuetify] },
  })
}

describe('ConfidenceChip', () => {
  it('reports high confidence for an exact identifier match', () => {
    const chip = render({
      confidence: 'CONFIDENCE_HIGH',
      joinTier: 1,
      vendorCount: 2,
    })
    expect(chip.text()).toContain('High')
  })

  it('reports medium confidence for a clean heuristic match', () => {
    const chip = render({
      confidence: 'CONFIDENCE_MEDIUM',
      joinTier: 2,
      vendorCount: 2,
    })
    expect(chip.text()).toContain('Medium')
  })

  // A single-vendor record involved no join at all, so presenting a confidence level
  // would answer a question nobody asked — and a green tick would imply corroboration
  // that does not exist.
  it('says "single vendor" rather than scoring a join that never happened', () => {
    const chip = render({
      confidence: 'CONFIDENCE_HIGH',
      joinTier: 2,
      vendorCount: 1,
    })
    expect(chip.text()).toContain('Single vendor')
    expect(chip.text()).not.toContain('High')
  })

  // The low state must be visually distinct, not merely differently coloured: an
  // uncertain join sitting at the same weight as a certain one teaches analysts to
  // trust joins that have not earned it.
  it('renders a low-confidence join at a lighter visual weight', () => {
    const low = render({ confidence: 'CONFIDENCE_LOW', joinTier: 2, vendorCount: 2 })
    const high = render({ confidence: 'CONFIDENCE_HIGH', joinTier: 1, vendorCount: 2 })

    expect(low.find('.v-chip--variant-outlined').exists()).toBe(true)
    expect(high.find('.v-chip--variant-tonal').exists()).toBe(true)
  })

  it('explains a shared client address in the accessible label', () => {
    const chip = render({
      confidence: 'CONFIDENCE_LOW',
      joinTier: 2,
      vendorCount: 2,
      ipShared: true,
    })
    const label = chip.find('.v-chip').attributes('aria-label') ?? ''
    expect(label).toContain('shared')
  })

  it('explains competing candidates in the accessible label', () => {
    const chip = render({
      confidence: 'CONFIDENCE_LOW',
      joinTier: 2,
      vendorCount: 2,
      candidateCount: 4,
    })
    const label = chip.find('.v-chip').attributes('aria-label') ?? ''
    expect(label).toContain('4 events')
    expect(label).toContain('wrong one')
  })

  // THE FALSE ALARM THIS REMOVES. An exact join rests on an identifier every member
  // carries, so nothing competed — a Worker-protected request legitimately produces two
  // Cloudflare rows, the client-facing request and the fetch to the origin. Reading that
  // as two candidates for one slot told analysts the partner "may be the wrong one" on
  // 95.8% of exact joins in production.
  //
  // Checked in the component as well as in the correlator so records written before the
  // fix stop showing it immediately, rather than only once they age out.
  it('does not claim candidates competed when an identifier did the joining', () => {
    const chip = render({
      confidence: 'CONFIDENCE_HIGH',
      joinTier: 1,
      vendorCount: 4,
      candidateCount: 2,
    })
    const label = chip.find('.v-chip').attributes('aria-label') ?? ''
    expect(label).not.toContain('competed')
    expect(label).not.toContain('wrong one')
  })

  it('falls back to an explicit unknown rather than implying confidence', () => {
    const chip = render({ vendorCount: 2 })
    expect(chip.text()).toContain('Unknown')
  })
})
