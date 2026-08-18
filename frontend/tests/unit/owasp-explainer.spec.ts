import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createPinia, setActivePinia } from 'pinia'

const post = vi.fn()
vi.mock('@/api/client', () => ({
  api: { POST: (...args: unknown[]) => post(...args) },
  toDisplayMessage: (err: unknown) => (err as { message: string }).message,
}))

import OwaspExplainer from '@/components/OwaspExplainer.vue'

// jsdom has no ResizeObserver, and Vuetify's progress and table components observe
// themselves to size. Without this every mount throws before a single assertion.
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
)

const vuetify = createVuetify({ components, directives })

function render() {
  setActivePinia(createPinia())
  return mount(OwaspExplainer, {
    props: {
      eventId: 'f5-event',
      receivedAt: '2026-08-18T04:29:11Z',
      sourceVendor: 'f5',
    },
    global: { plugins: [vuetify] },
  })
}

async function shown(result: Record<string, unknown>) {
  post.mockResolvedValue({ data: result })
  const view = render()
  await flushPromises()
  return view
}

function match(overrides: Record<string, unknown> = {}) {
  return {
    id: 942100,
    message: 'SQL Injection Attack Detected via libinjection',
    severity: 'critical',
    category: 'attack-sqli',
    score: 5,
    ...overrides,
  }
}

beforeEach(() => post.mockReset())

describe('OwaspExplainer', () => {
  // THE WHOLE POINT. Cloudflare says "949110: Inbound Anomaly Score Exceeded" and stops.
  // The contributors and what each one added are the half that is missing, and 949110
  // itself is the decision — showing it among the contributors makes it look like one.
  it('names the rules behind the score and leaves 949110 out of them', async () => {
    const view = await shown({
      available: true,
      blockingScore: 20,
      threshold: 40,
      paranoiaLevel: 1,
      wouldBlock: false,
      matched: [
        match(),
        match({ id: 942190, message: 'Detects MSSQL code execution' }),
        match({ id: 949110, message: 'Inbound Anomaly Score Exceeded', score: 0 }),
      ],
    })

    expect(view.text()).toContain('942100')
    expect(view.text()).toContain('+5')
    expect(view.text()).toContain('score 20 of 40')
    expect(view.text()).not.toContain('949110')
  })

  // Heaviest first: a rule contributing 5 of a score of 20 is a different finding from one
  // contributing 1, and the reader should not have to hunt for it.
  it('puts the biggest contributor first', async () => {
    const view = await shown({
      available: true,
      matched: [match({ id: 913100, score: 2 }), match({ id: 942100, score: 5 })],
    })

    const rows = view.findAll('tbody tr').map((row) => row.text())
    expect(rows).toHaveLength(2)
    expect(rows[0]).toContain('942100')
    expect(rows[1]).toContain('913100')
  })

  // THE ONE THAT PREVENTS A WRONG CONCLUSION. On this deployment every OWASP hit is an
  // upload and F5 keeps about two kilobytes of it, so a clean reading usually means the
  // deciding bytes were never captured. Presented plainly it would read as "this request
  // is fine", which is the opposite of what it means.
  it('warns when the reading was made on a fraction of the body', async () => {
    const view = await shown({
      available: true,
      matched: [],
      bodyEvaluated: 2152,
      bodyDeclared: 132914,
      bodyTruncated: true,
    })

    expect(view.text()).toContain('2,152')
    expect(view.text()).toContain('132,914')
    expect(view.text()).toContain('has not been ruled out')
  })

  // A request that has aged out is not a request with no findings.
  it('shows why no reading could be made, rather than an empty list', async () => {
    const view = await shown({
      available: false,
      error: 'the request as the vendor logged it is no longer retained',
    })

    expect(view.text()).toContain('no longer retained')
    expect(view.text()).not.toContain('No OWASP rule matched')
  })

  // Distinct from "nothing was evaluated": with a whole body read and no rule matched, the
  // request really is clean as far as OWASP is concerned.
  it('says plainly when nothing matched', async () => {
    const view = await shown({ available: true, matched: [], bodyEvaluated: 0 })

    expect(view.text()).toContain('No OWASP rule matched')
  })

  // A rule that fired on the truncated capture is not a finding about the request, and
  // chasing it would waste the reader's afternoon.
  it('marks a rule that fired on how the request was captured', async () => {
    const view = await shown({
      available: true,
      matched: [match({ id: 200002, message: 'Failed to parse request body', artifact: true })],
    })

    expect(view.text()).toContain('not on the request itself')
  })

  // The lookup cannot prune without these, and the panel would time out instead of
  // answering — so they have to be on the request.
  it('sends what the payload lookup needs to seek', async () => {
    await shown({ available: true, matched: [] })

    const [path, options] = post.mock.calls[0] as [string, { body: Record<string, unknown> }]
    expect(path).toBe('/api/v1/waf-migration/owasp')
    expect(options.body.eventId).toBe('f5-event')
    expect(options.body.receivedAt).toBe('2026-08-18T04:29:11Z')
    expect(options.body.sourceVendor).toBe('f5')
  })
})
