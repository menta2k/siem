import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

import AsmFindings from '@/components/AsmFindings.vue'

const vuetify = createVuetify({ components, directives })

/** A real blocked request from production, as the API returns it. */
const findings = {
  violationRating: '4',
  violations: [
    {
      title: 'Attack signature detected',
      name: 'VIOL_ATTACK_SIGNATURE',
      severity: 'error',
      description: 'The system checks that the request does not match an attack signature.',
    },
    {
      title: 'Illegal cross-origin request',
      name: 'VIOL_CROSS_ORIGIN_REQUEST',
      severity: 'critical',
      attackType: 'Cross-site Request Forgery',
      risk: 'An attacker can perform actions on behalf of an authenticated user.',
    },
  ],
  signatures: [
    {
      // A string, not a number: protobuf's JSON mapping encodes uint64 as a string so
      // it survives a language whose numbers stop being exact at 2^53.
      id: '200004165',
      name: 'Executable code file upload',
      accuracy: 'high',
      risk: 'high',
      attackType: 'Other Application Attacks',
      cves: ['CVE-2012-2902', 'CVE-2018-9206'],
      description: 'Summary:\nAn upload of an executable file was attempted.\n\nImpact:\nSerious.',
    },
  ],
}

function render(overrides = {}) {
  return mount(AsmFindings, {
    props: { findings: { ...findings, ...overrides } },
    global: { plugins: [vuetify] },
  })
}

describe('ASM findings', () => {
  it('names every violation and signature the appliance reported', () => {
    const text = render().text()

    expect(text).toContain('Attack signature detected')
    expect(text).toContain('Illegal cross-origin request')
    expect(text).toContain('Executable code file upload')
    expect(text).toContain('200004165')
  })

  // The pivot into every other tool the analyst owns. If the CVEs are dropped, the
  // panel is prettier than the raw payload but no more useful.
  it('surfaces the CVEs', () => {
    const text = render().text()

    expect(text).toContain('CVE-2012-2902')
    expect(text).toContain('CVE-2018-9206')
  })

  it('shows the threat rating out of five', () => {
    expect(render().text()).toContain('threat rating 4/5')
  })

  // A violation the bundled catalogue does not carry must still appear, saying so,
  // rather than vanishing — the record states it fired, and showing three violations
  // where the appliance reported four is the one outcome worse than no description.
  it('keeps an unresolved violation and admits it is unresolved', () => {
    const wrapper = render({
      violations: [{ title: 'Some Future Violation' }],
    })

    const text = wrapper.text()
    expect(text).toContain('Some Future Violation')
    expect(text).toContain('Not in the bundled ASM catalogue')
  })

  // Accuracy is the false-positive likelihood, so LOW accuracy is the alarming value.
  // Colouring it like a low risk would invert the meaning of the chip.
  it('colours low accuracy as a problem and high accuracy as reassurance', () => {
    const low = render({
      signatures: [{ id: '1', name: 'x', accuracy: 'low', risk: 'low' }],
    })
    expect(low.html()).toContain('text-error')

    const high = render({
      signatures: [{ id: '2', name: 'y', accuracy: 'high', risk: 'low' }],
    })
    expect(high.html()).toContain('text-success')
  })

  // Vendor-supplied prose is rendered as text. It is the field an injected payload
  // would arrive in if a signature description were ever attacker-influenced.
  it('renders descriptions as text rather than markup', () => {
    const wrapper = render({
      violations: [
        {
          title: 'Injected',
          name: 'VIOL_X',
          severity: 'error',
          risk: '<img src=x onerror=alert(1)>',
        },
      ],
    })

    expect(wrapper.html()).not.toContain('<img src=x')
    expect(wrapper.text()).toContain('<img src=x onerror=alert(1)>')
  })
})
