import { describe, expect, it, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'

import WafTuning from '@/pages/WafTuning.vue'

// jsdom has no ResizeObserver, and Vuetify's tab strip observes its container. Without
// this the page throws before rendering anything.
globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const vuetify = createVuetify({
  components: vuetifyComponents,
  directives: vuetifyDirectives,
})

const get = vi.fn()
vi.mock('@/api/client', () => ({
  api: { GET: (...args: unknown[]) => get(...args) },
  toDisplayMessage: (e: unknown) => (e as Error).message,
}))

/** Routes each endpoint to its own fixture, since the page fetches several at once. */
function respondWith(rules: unknown[], gaps: unknown[] = []) {
  get.mockImplementation((path?: string) => {
    if (path?.includes('/gaps')) return Promise.resolve({ data: { gaps } })
    if (path?.includes('/rules')) return Promise.resolve({ data: { rules } })
    return Promise.resolve({ data: {} })
  })
}

async function render(rules: unknown[], gaps: unknown[] = []) {
  respondWith(rules, gaps)
  const wrapper = mount(WafTuning, { global: { plugins: [vuetify] } })
  await flushPromises()
  return wrapper
}

beforeEach(() => get.mockReset())

describe('WAF tuning', () => {
  // THE READING IS THE POINT OF THE PAGE, and it turns entirely on a scale that runs
  // backwards. A rule firing on score-2 traffic is working; the same rule firing on
  // score-95 traffic is arguing with the WAF's own model. Getting these the wrong way
  // round would recommend exempting real attacks.
  it('reads a low-scoring rule as attacks and a high-scoring one as clean', async () => {
    const wrapper = await render([
      {
        ruleId: 'sqli',
        ruleDescription: 'SQLi - Equation - URI',
        requestHost: 'api.example.com',
        action: 'log',
        source: 'firewallManaged',
        events: '10',
        attackEvents: '10',
        suspiciousEvents: '0',
        cleanEvents: '0',
      },
      {
        ruleId: 'infodisc',
        ruleDescription: 'Information Disclosure',
        requestHost: 'shop.example.com',
        action: 'log',
        source: 'firewallManaged',
        events: '10',
        attackEvents: '0',
        suspiciousEvents: '0',
        cleanEvents: '10',
      },
    ])

    const text = wrapper.text()
    expect(text).toContain('scores as attacks')
    expect(text).toContain('scores as clean')
    // The clean reading has to say WHY it matters, or it reads as reassurance.
    expect(text).toContain('the WAF disagrees with this rule')
  })

  // A skip rule is an exemption, not a detection. Scoring it like one would report the
  // single biggest lever on a ruleset as though it were a well-behaved rule.
  it('reports a skip rule as exempting traffic rather than as a detection', async () => {
    const wrapper = await render([
      {
        ruleId: 'allowlist',
        ruleDescription: 'Disable protection for chat',
        requestHost: 'chat.example.com',
        action: 'skip',
        source: 'firewallCustom',
        events: '350000',
        attackEvents: '0',
        suspiciousEvents: '0',
        cleanEvents: '350000',
      },
    ])

    const text = wrapper.text()
    expect(text).toContain('exempting traffic')
    expect(text).toContain('bypassed the rules behind this')
  })

  // The scale is stated once, plainly, on the one screen where reading it backwards
  // would do real damage.
  it('states which direction the score runs', async () => {
    const wrapper = await render([])
    expect(wrapper.text()).toContain('1 to 100 with low meaning attack')
  })

  // A quiet window is normal for log-mode rules and must not look like a broken page.
  it('explains an empty result rather than showing a blank table', async () => {
    const wrapper = await render([])
    expect(wrapper.text()).toContain('No rule matched in this window')
  })

  it('lists coverage gaps as hosts taking unmatched attacks', async () => {
    const wrapper = await render(
      [],
      [{ requestHost: 'api.example.com', events: '15', attackEvents: '12', suspiciousEvents: '3' }],
    )

    await wrapper.findAll('.v-tab')[1]?.trigger('click')
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('api.example.com')
    expect(text).toContain('no rule matched')
  })
})
