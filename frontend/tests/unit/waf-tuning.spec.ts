import { describe, expect, it, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'

import { createPinia } from 'pinia'

import WafTuning from '@/pages/WafTuning.vue'

// No router is mounted, so router-link would not resolve to an anchor at all. The stub
// serialises its destination into the href, which is what these tests actually care
// about: that the link carries the right rule and window, not how Vue renders it.
const RouterLinkStub = {
  props: ['to'],
  template: '<a :href="JSON.stringify(to)"><slot /></a>',
}

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
function respondWith(rules: unknown[], gaps: unknown[] = [], samples: unknown[] = []) {
  get.mockImplementation((path?: string) => {
    if (path?.includes('/gaps')) return Promise.resolve({ data: { gaps } })
    if (path?.includes('/samples')) return Promise.resolve({ data: { samples } })
    if (path?.includes('/paths')) return Promise.resolve({ data: { paths: [] } })
    if (path?.includes('/corroboration')) return Promise.resolve({ data: {} })
    if (path?.includes('/rules')) return Promise.resolve({ data: { rules } })
    return Promise.resolve({ data: {} })
  })
}

async function render(rules: unknown[], gaps: unknown[] = [], samples: unknown[] = []) {
  respondWith(rules, gaps, samples)
  const wrapper = mount(WafTuning, {
    global: {
      plugins: [vuetify, createPinia()],
      stubs: { RouterLink: RouterLinkStub },
    },
  })
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
        reading: 'attacks',
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
        reading: 'clean',
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
        reading: 'exempting',
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

  // THE FILTERS MUST REACH THE SERVER. Rules are ordered by volume, so an allowlist
  // matching 350,000 requests outranks a detection matching ten — filtering the response
  // in the browser would return an empty list for exactly the rules worth finding, and
  // would do it silently.
  it('sends both filters to the server rather than filtering the response', async () => {
    const wrapper = await render([])

    const selects = wrapper.findAllComponents({ name: 'VSelect' })
    // Range, action, reading — the action select is the second.
    await selects[1]?.setValue('log')
    await flushPromises()

    // The LAST matching call, not the first: the initial load fires before the filter is
    // set, and finding that one would assert against an empty filter and always pass.
    const calls = get.mock.calls.filter((c) => String(c[0]).includes('/waf-tuning/rules'))
    expect(calls.at(-1)?.[1]?.params?.query?.action).toBe('log')
  })

  // The reading decides which rows a filter returns, so recomputing it in the browser
  // would eventually label a row one thing while a filter for that thing excluded it.
  it('renders the reading the server computed rather than deriving its own', async () => {
    // Bands that a client-side rule would read as "attacks", labelled `clean` by the
    // server. The label shown must follow the server.
    const wrapper = await render([
      {
        ruleId: 'x',
        ruleDescription: 'Disagreeing rule',
        requestHost: 'h',
        action: 'log',
        source: 'firewallManaged',
        events: '10',
        attackEvents: '10',
        suspiciousEvents: '0',
        cleanEvents: '0',
        reading: 'clean',
      },
    ])

    expect(wrapper.text()).toContain('scores as clean')
    expect(wrapper.text()).not.toContain('scores as attacks')
  })

  it('says so when filters exclude everything, rather than looking broken', async () => {
    const wrapper = await render([])

    const selects = wrapper.findAllComponents({ name: 'VSelect' })
    await selects[2]?.setValue('attacks')
    await flushPromises()

    expect(wrapper.text()).toContain('No rule matches these filters')
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

describe('WAF tuning rule samples', () => {
  const rule = {
    ruleId: 'sqli',
    ruleDescription: 'SQLi - Equation - URI',
    requestHost: 'www.jobs.bg',
    action: 'log',
    source: 'firewallManaged',
    events: '10',
    attackEvents: '10',
    suspiciousEvents: '0',
    cleanEvents: '0',
    reading: 'attacks',
  }

  // A real detection from production. The query string is the point: the aggregates say
  // this rule fires ten times, and only the request itself says whether that was an
  // injection or a product filter.
  const sample = {
    eventId: 'abc123',
    eventTime: '2026-08-14T10:00:00Z',
    clientIp: '203.0.113.10',
    country: 'US',
    requestHost: 'www.jobs.bg',
    requestPath: '/',
    requestQuery: 'a=%27or%201=1%27',
    requestMethod: 'GET',
    httpStatus: 200,
    attackScore: 2,
    verdict: 'monitored',
  }

  it('shows the request that actually matched, query string included', async () => {
    const wrapper = await render([rule], [], [sample])
    await wrapper.findAll('tbody tr')[0]?.trigger('click')
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('Sample requests')
    expect(text).toContain('203.0.113.10')
    // The payload itself — without it the sample answers nothing the counts did not.
    expect(text).toContain('a=%27or%201=1%27')
  })

  // The query string is attacker-controlled and is exactly where an injected payload
  // would arrive. It must render as text.
  it('renders an attacker-controlled query as text, not markup', async () => {
    const wrapper = await render(
      [rule],
      [],
      [{ ...sample, requestQuery: '<img src=x onerror=alert(1)>' }],
    )
    await wrapper.findAll('tbody tr')[0]?.trigger('click')
    await flushPromises()

    expect(wrapper.html()).not.toContain('<img src=x')
    expect(wrapper.text()).toContain('<img src=x onerror=alert(1)>')
  })

  // A handful of samples judges a rule; it does not investigate one. The link hands that
  // to the page built for it, carrying the same rule and window.
  it('links to the full search for the same rule and window', async () => {
    const wrapper = await render([rule], [], [sample])
    await wrapper.findAll('tbody tr')[0]?.trigger('click')
    await flushPromises()

    const link = wrapper.findAll('a').find((a) => a.text().includes('open all in search'))
    expect(link?.attributes('href')).toContain('sqli')
    // Carries the window too, so the search opens on the same evidence.
    expect(link?.attributes('href')).toContain('from')
  })

  it('says so when the window holds no matching requests', async () => {
    const wrapper = await render([rule], [], [])
    await wrapper.findAll('tbody tr')[0]?.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('No matching requests remain')
  })
})
