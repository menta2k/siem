import { beforeEach, describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

import { VTooltip } from 'vuetify/components'

import CorrelationHealthChip from '@/components/CorrelationHealthChip.vue'

const vuetify = createVuetify({ components, directives })

function render(health: Record<string, unknown> | null) {
  return mount(CorrelationHealthChip, {
    props: { health },
    global: { plugins: [vuetify, createPinia()] },
  })
}

/**
 * The tooltip is what explains the chip, and Vuetify only renders it on activation —
 * so it is read from the prop rather than from the DOM. Asserting on the chip's text
 * alone would leave the sentence an operator actually acts on untested.
 */
function tooltipOf(chip: ReturnType<typeof render>): string {
  return String(chip.findComponent(VTooltip).props('text'))
}

describe('CorrelationHealthChip', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  // The state that ran for hours on production while every chart on the page looked
  // normal, because they were all showing records written before the pipeline stopped.
  it('names data loss as loss, not as slowness', () => {
    const chip = render({
      status: 'losing',
      eventsFiled: 172000,
      recordsEmitted: 900,
      windowsDroppedEmpty: 1701942,
      claimLagMs: 90 * 60 * 1000,
      windowTtlMs: 19 * 60 * 1000,
    })

    expect(chip.text()).toContain('Losing correlations')
    // The count is what makes it undeniable — and the lag against the window lifetime
    // is what tells an operator it will not fix itself.
    expect(tooltipOf(chip)).toContain('1,701,942')
    expect(tooltipOf(chip)).toContain('19 min')
  })

  it('warns while there is still margin left', () => {
    const chip = render({
      status: 'behind',
      claimLagMs: 12 * 60 * 1000,
      windowTtlMs: 19 * 60 * 1000,
      windowsDue: 315000,
    })

    expect(chip.text()).toContain('Behind')
    expect(tooltipOf(chip)).toContain('315,000')
  })

  it('reports a stall with the count that proves it is one', () => {
    const chip = render({ status: 'stalled', eventsFiled: 172000, recordsEmitted: 0 })

    expect(chip.text()).toContain('Stalled')
    expect(tooltipOf(chip)).toContain('172,000')
  })

  it('distinguishes a quiet tenant from a broken one', () => {
    expect(render({ status: 'idle', eventsFiled: 0 }).text()).toContain('Idle')
    expect(render({ status: 'healthy', eventsFiled: 10, recordsEmitted: 10 }).text()).toContain(
      'Healthy',
    )
  })

  // A processor that predates the health table reports nothing. That must read as "not
  // reported" — claiming health on the strength of no data is the failure mode this
  // whole panel exists to end.
  it('does not claim health when nothing was reported', () => {
    expect(render(null).text()).toContain('Unavailable')
    expect(render({}).text()).toContain('Unavailable')
  })
})
