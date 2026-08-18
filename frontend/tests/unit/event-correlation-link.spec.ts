import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'
import { createPinia, setActivePinia } from 'pinia'

const get = vi.fn()
const post = vi.fn()
vi.mock('@/api/client', () => ({
  api: {
    GET: (...args: unknown[]) => get(...args),
    POST: (...args: unknown[]) => post(...args),
  },
  // The page's imports reach the whole module, so the parts it does not exercise still
  // have to exist.
  configureAuth: () => {},
  toDisplayMessage: (err: unknown) => (err as Error).message,
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: {} }),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}))

import Search from '@/pages/Search.vue'

globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

// The detail is a Vuetify dialog, and its overlay reads the visual viewport to position
// itself. jsdom has no such thing, so without this the dialog throws instead of opening.
vi.stubGlobal('visualViewport', {
  width: 1024,
  height: 768,
  offsetLeft: 0,
  offsetTop: 0,
  scale: 1,
  addEventListener() {},
  removeEventListener() {},
})

const vuetify = createVuetify({
  components: vuetifyComponents,
  directives: vuetifyDirectives,
})

// Serialises its destination into the href, which is what these tests care about.
const RouterLinkStub = {
  props: ['to'],
  template: '<a :href="JSON.stringify(to)"><slot /></a>',
}

const EVENT_ID = 'd1a19ac1024a7c411f93567f5aa2d6965fd6da36ee7568b2c547903cce640379'

/** Opens the detail dialog for one event, with the detail the server returned. */
async function openDetail(detail: Record<string, unknown>) {
  setActivePinia(createPinia())
  post.mockResolvedValue({
    data: {
      items: [{ eventId: EVENT_ID, vendor: 'VENDOR_CLOUDFLARE', verdict: 'VERDICT_MONITORED' }],
      page: {},
    },
  })
  get.mockResolvedValue({ data: detail })

  document.body.innerHTML = ''
  const view = mount(Search, {
    global: {
      plugins: [vuetify, createPinia()],
      stubs: { RouterLink: RouterLinkStub, 'router-link': RouterLinkStub },
    },
  })
  await flushPromises()

  await view.find('tbody tr').trigger('click')
  await flushPromises()
  return view
}

/**
 * Every destination the open dialog links to.
 *
 * Read from the document rather than the wrapper: a Vuetify dialog teleports its content
 * to the body, so nothing inside it is a descendant of the mounted component.
 */
function links(): string[] {
  return [...document.body.querySelectorAll('a')].map((a) => a.getAttribute('href') ?? '')
}

/** The dialog's text, from the same place. */
function dialogText(): string {
  return document.body.textContent ?? ''
}

beforeEach(() => {
  get.mockReset()
  post.mockReset()
})

describe('the link from an event to its correlation', () => {
  // THE POINT. An analyst reading one vendor's verdict always asks what the others did
  // with the same request, and until now the detail view could not say — an event does not
  // carry a correlation id, so nothing on screen led anywhere.
  it('links straight to the correlated record when there is one', async () => {
    await openDetail({
      summary: { eventId: EVENT_ID, vendorRequestId: 'a2c90f883c2de5b6' },
      correlationId: '78ce7e59-1af7-49f2-a5a4-77caff740f01',
    })

    const target = links().find((href) => href.includes('78ce7e59'))
    expect(target).toBeTruthy()
    expect(target).toContain('correlated')
    expect(dialogText()).toContain('Every vendor that saw this request')
  })

  // A correlation is written when the join window closes, so a very recent event has none
  // yet. A dead end would read as "no other vendor saw this", which is a different and
  // much stronger claim — the ray still identifies the request.
  it('falls back to the ray lookup when no record has joined yet', async () => {
    await openDetail({
      summary: { eventId: EVENT_ID, vendorRequestId: 'a2c90f883c2de5b6' },
    })

    const target = links().find((href) => href.includes('a2c90f883c2de5b6'))
    expect(target).toBeTruthy()
    expect(target).toContain('correlated-list')
    expect(dialogText()).toContain('no correlated record yet')
  })

  // Nothing to link to and nothing to search with: the row is absent rather than dangling.
  it('offers nothing when the event carries no request id either', async () => {
    await openDetail({ summary: { eventId: EVENT_ID } })

    expect(dialogText()).not.toContain('Full request')
  })
})
