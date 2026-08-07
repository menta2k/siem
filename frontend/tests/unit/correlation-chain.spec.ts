import { describe, expect, it, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'

import CorrelationChain from '@/components/CorrelationChain.vue'

// jsdom has no ResizeObserver, and Vuetify's timeline observes its container. Without
// this the component throws before rendering anything.
globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const vuetify = createVuetify({
  components: vuetifyComponents,
  directives: vuetifyDirectives,
})

/** Mounts with the real Vuetify components, so the rendered markup is what ships. */
function render(eventIds: string[], conflicting?: Set<string>) {
  return mount(CorrelationChain, {
    props: { eventIds, conflicting },
    global: { plugins: [vuetify] },
  })
}

const get = vi.fn()
vi.mock('@/api/client', () => ({
  api: { GET: (...args: unknown[]) => get(...args) },
  toDisplayMessage: (e: unknown) => (e as Error).message,
}))

function event(id: string, vendor: string, time: string, verdict: string) {
  return {
    data: {
      summary: { eventId: id, vendor, eventTime: time, verdict, ruleId: `rule-${id}` },
      rawPayload: `payload-${id}`,
      rawExtra: { note: `extra-${id}` },
    },
  }
}

beforeEach(() => {
  get.mockReset()
})

describe('CorrelationChain', () => {
  // The chain's whole purpose is showing WHO SAW IT FIRST. Rendering in the order the
  // ids happened to be stored would misrepresent the sequence of observations, which is
  // the thing an analyst reads it for.
  it('orders events by observation time, not by the order of the ids', async () => {
    get.mockImplementation((_path: string, opts: { params: { path: { eventId: string } } }) => {
      const id = opts.params.path.eventId
      const times: Record<string, string> = {
        late: '2026-08-07T10:00:02.000Z',
        early: '2026-08-07T10:00:00.000Z',
        middle: '2026-08-07T10:00:01.000Z',
      }
      return Promise.resolve(event(id, 'VENDOR_F5', times[id]!, 'VERDICT_ALLOWED'))
    })

    const wrapper = render(['late', 'early', 'middle'])
    await flushPromises()

    const text = wrapper.text()
    expect(text.indexOf('rule-early')).toBeLessThan(text.indexOf('rule-middle'))
    expect(text.indexOf('rule-middle')).toBeLessThan(text.indexOf('rule-late'))
  })

  // The offset is what explains the join: vendors sit at different points in the request
  // path, and the spread is what the correlation window has to accommodate.
  it('shows each event offset from the first observation', async () => {
    get.mockImplementation((_p: string, opts: { params: { path: { eventId: string } } }) => {
      const id = opts.params.path.eventId
      const times: Record<string, string> = {
        a: '2026-08-07T10:00:00.000Z',
        b: '2026-08-07T10:00:00.250Z',
        c: '2026-08-07T10:00:03.000Z',
      }
      return Promise.resolve(event(id, 'VENDOR_CLOUDFLARE', times[id]!, 'VERDICT_ALLOWED'))
    })

    const wrapper = render(['a', 'b', 'c'])
    await flushPromises()

    expect(wrapper.text()).toContain('first')
    expect(wrapper.text()).toContain('+250 ms')
    expect(wrapper.text()).toContain('+3.00 s')
  })

  // THE IMPORTANT FAILURE MODE. An event aged out by retention must not blank the whole
  // chain — the events that remain are still evidence, and a silently empty row reads as
  // "this vendor saw nothing", which is a different and much worse claim.
  it('keeps the rest of the chain when one event cannot be loaded', async () => {
    get.mockImplementation((_p: string, opts: { params: { path: { eventId: string } } }) => {
      const id = opts.params.path.eventId
      if (id === 'gone') return Promise.reject(new Error('event not found'))
      return Promise.resolve(
        event(id, 'VENDOR_DATADOME', '2026-08-07T10:00:00.000Z', 'VERDICT_BLOCKED'),
      )
    })

    const wrapper = render(['ok1', 'gone', 'ok2'])
    await flushPromises()

    expect(wrapper.text()).toContain('event not found')
    expect(wrapper.text()).toContain('rule-ok1')
    expect(wrapper.text()).toContain('rule-ok2')
  })

  // An unbounded fan-out from a detail page turns one click into a request storm.
  it('bounds how many events it fetches', async () => {
    get.mockResolvedValue(event('x', 'VENDOR_F5', '2026-08-07T10:00:00.000Z', 'VERDICT_ALLOWED'))

    render(Array.from({ length: 200 }, (_, i) => `e${i}`))
    await flushPromises()

    expect(get.mock.calls.length).toBeLessThanOrEqual(25)
  })

  it('renders nothing to fetch when the record lists no events', async () => {
    render([])
    await flushPromises()

    expect(get).not.toHaveBeenCalled()
  })
})
