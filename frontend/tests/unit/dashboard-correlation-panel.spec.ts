import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'
import { createPinia, setActivePinia } from 'pinia'

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
// The auth store pulls configureAuth and ApiRequestError from the same module, and
// mounting a page mounts the store with it.
vi.mock('@/api/client', () => ({
  api: { GET: (...args: unknown[]) => get(...args) },
  toDisplayMessage: (e: unknown) => (e as Error).message,
  configureAuth: () => {},
  ApiRequestError: class extends Error {},
}))

import Dashboards from '@/pages/Dashboards.vue'

const OVERVIEW = { totalEvents: '4210', totalBlocked: '317', points: [] }

/** Every panel answers except the ones a test chooses to break. */
function respondWith(overrides: Record<string, unknown> = {}) {
  get.mockImplementation((path?: string) => {
    for (const [fragment, response] of Object.entries(overrides)) {
      if (path?.includes(fragment)) {
        return response instanceof Error ? Promise.reject(response) : Promise.resolve(response)
      }
    }
    if (path?.includes('/overview')) return Promise.resolve({ data: OVERVIEW })
    return Promise.resolve({ data: {} })
  })
}

async function render(overrides: Record<string, unknown> = {}) {
  respondWith(overrides)
  const wrapper = mount(Dashboards, {
    global: { plugins: [vuetify, createPinia()] },
  })
  await flushPromises()
  await flushPromises()
  return wrapper
}

describe('Dashboards correlation panel', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    get.mockReset()
  })

  it('shows the pipeline verdict the server reported', async () => {
    const page = await render({
      '/correlation-health': { data: { status: 'losing', eventsFiled: '172000' } },
    })

    expect(page.text()).toContain('Correlation pipeline')
    expect(page.text()).toContain('Losing correlations')
  })

  // WHAT THIS SHIPPED AS. Fetched in the same Promise.all as everything else, one 500
  // from this endpoint blanked the WHOLE dashboard — no events, no rules, no feeds,
  // just "an internal error occurred" across a page whose other five panels had all
  // answered. The panel that reports the pipeline is unhealthy must never be able to
  // take down the panels showing what the pipeline produced.
  it('cannot take the rest of the dashboard down with it', async () => {
    const page = await render({
      '/correlation-health': new Error('an internal error occurred'),
    })

    // The traffic the page exists to show is still there.
    expect(page.text()).toContain('4210')
    expect(page.text()).not.toContain('an internal error occurred')
    // And the panel says it does not know, rather than claiming health.
    expect(page.text()).toContain('Unavailable')
  })
})
