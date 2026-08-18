import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'
import { createPinia, setActivePinia } from 'pinia'

const post = vi.fn()
vi.mock('@/api/client', () => ({
  api: { POST: (...args: unknown[]) => post(...args) },
  toDisplayMessage: (err: unknown) => (err as Error).message,
}))

// The page reads its identifiers off the route it was linked with.
const query = { ray: '' as string | undefined, supportId: undefined as string | undefined }
vi.mock('vue-router', () => ({
  useRoute: () => ({ query }),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

import Correlated from '@/pages/Correlated.vue'

globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const vuetify = createVuetify({
  components: vuetifyComponents,
  directives: vuetifyDirectives,
})

const RouterLinkStub = {
  props: ['to'],
  template: '<a :href="JSON.stringify(to)"><slot /></a>',
}

async function open(routeQuery: Record<string, string | undefined>) {
  query.ray = routeQuery.ray
  query.supportId = routeQuery.supportId
  setActivePinia(createPinia())

  const view = mount(Correlated, {
    global: {
      plugins: [vuetify, createPinia()],
      stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub },
    },
  })
  await flushPromises()
  return view
}

/** The window the page asked the server for, in hours. */
function requestedHours(): number {
  const [, options] = post.mock.calls[0] as [
    string,
    { body: { timeRange: Record<string, string> } },
  ]
  const { from, to } = options.body.timeRange
  return (Date.parse(to ?? '') - Date.parse(from ?? '')) / 3_600_000
}

beforeEach(() => {
  post.mockReset()
  post.mockResolvedValue({ data: { items: [], page: {} } })
})

describe('Correlated, opened for one request', () => {
  // THE BUG. The console links from an event to its full request by ray, and this page
  // browses the last hour by default. A seventeen-hour-old event reported as having no
  // correlation when the record was there the whole time — the window on screen had
  // nothing to do with when the request happened, and nothing said so.
  it('opens a window that can contain the request it was linked to', async () => {
    await open({ ray: 'a2c90f883c2de5b6' })

    expect(requestedHours()).toBeGreaterThanOrEqual(24)
    const [, options] = post.mock.calls[0] as [
      string,
      { body: { filters: Record<string, string> } },
    ]
    expect(options.body.filters.vendorRequestId).toBe('a2c90f883c2de5b6')
  })

  it('does the same for an F5 support id', async () => {
    await open({ supportId: '2773644994017383095' })

    expect(requestedHours()).toBeGreaterThanOrEqual(24)
  })

  // Browsing is a different question from looking one request up, and a wide default there
  // would read a week of correlated records to fill a table nobody narrowed.
  it('keeps the short default when nothing was linked to', async () => {
    await open({})

    expect(requestedHours()).toBe(1)
  })
})
