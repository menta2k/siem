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

import ExpressionTester from '@/components/ExpressionTester.vue'

// jsdom has no ResizeObserver, and Vuetify's auto-growing textarea observes itself to size
// as the expression is typed. Without this every mount throws before a single assertion.
vi.stubGlobal(
  'ResizeObserver',
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
)

const vuetify = createVuetify({ components, directives })
const range = { from: '2026-08-11T00:00:00Z', to: '2026-08-18T00:00:00Z' }

function render() {
  setActivePinia(createPinia())
  return mount(ExpressionTester, {
    props: {
      range,
      violation: 'Attack signature detected',
      requestHost: 'www.jobs.bg',
      requestMethod: 'POST',
      f5Verdict: 'blocked',
      cloudflareVerdict: 'allowed',
    },
    global: {
      plugins: [vuetify],
      // Vue re-throws an error that reaches a handler with nowhere to go, and vitest fails
      // the run on it — even for the failure this component is built to catch and display.
      config: { errorHandler: () => {} },
    },
  })
}

async function runTest(view: ReturnType<typeof render>, expression = 'http.host eq "x"') {
  await view.find('textarea').setValue(expression)
  await view
    .findAll('button')
    .find((b) => b.text().includes('Test'))
    ?.trigger('click')
  await flushPromises()
}

beforeEach(() => post.mockReset())

describe('ExpressionTester', () => {
  it('reports how many of the group a rule would catch', async () => {
    post.mockResolvedValue({
      data: {
        valid: true,
        tested: 4,
        matched: 4,
        outcomes: [{ eventId: 'e1', requestPath: '/js_file.php', matched: true }],
      },
    })

    const view = render()
    await runTest(view)

    expect(view.text()).toContain('4 of 4')
    expect(view.text()).toContain('catches every request here')
  })

  // Three states, not two. A rule catching SOME of a group is the interesting case: it
  // usually means the group holds more than one kind of request, which is a finding rather
  // than a failure.
  it('distinguishes catching some from catching none', async () => {
    post.mockResolvedValue({ data: { valid: true, tested: 4, matched: 2, outcomes: [] } })
    const partial = render()
    await runTest(partial)
    expect(partial.text()).toContain('catches some of them')

    post.mockResolvedValue({ data: { valid: true, tested: 4, matched: 0, outcomes: [] } })
    const none = render()
    await runTest(none)
    expect(none.text()).toContain('catches none of them')
  })

  // THE FAILURE THAT WOULD MAKE THIS WORSE THAN NOTHING. F5 keeps only a prefix of the
  // request, so a body expression that misses may be missing on the evidence. Presenting
  // that as a clean "0 of 4" would send someone off to rewrite a rule that was already
  // correct.
  it('says when a miss is uncertain rather than presenting it as a clean no', async () => {
    post.mockResolvedValue({
      data: {
        valid: true,
        tested: 2,
        matched: 0,
        uncertain: 1,
        outcomes: [
          {
            eventId: 'e1',
            requestPath: '/js_file.php',
            matched: false,
            caveat: 'only part of the body was captured',
          },
        ],
      },
    })

    const view = render()
    await runTest(view)

    expect(view.text()).toContain('uncertain')
    expect(view.text()).toContain('only part of the body was captured')
  })

  // A refused expression is an ANSWER and carries no counts: "0 of 20" beside the reason
  // would read as a result when the question was never asked.
  it('shows why an expression was refused, without a count', async () => {
    post.mockResolvedValue({
      data: {
        valid: false,
        error: 'the expression uses fields this tester cannot reconstruct',
        unavailableFields: ['cf.bot_management.score'],
      },
    })

    const view = render()
    await runTest(view)

    expect(view.text()).toContain('cannot reconstruct')
    expect(view.text()).toContain('cf.bot_management.score')
    expect(view.text()).not.toContain(' of ')
  })

  // No requests is not a failed test. Saying "0 matched" would claim the rule was judged.
  it('does not call an untested rule a failure', async () => {
    post.mockResolvedValue({ data: { valid: true, tested: 0, matched: 0, outcomes: [] } })

    const view = render()
    await runTest(view)

    expect(view.text()).toContain('has not been tested against anything')
    expect(view.text()).not.toContain('catches none')
  })

  it('sends the group and the expression to the server', async () => {
    post.mockResolvedValue({ data: { valid: true, tested: 1, matched: 1, outcomes: [] } })

    const view = render()
    await runTest(view, '  http.host eq "www.jobs.bg"  ')

    const [, options] = post.mock.calls[0] as [string, { body: Record<string, unknown> }]
    const body = options.body
    expect(body.expression).toBe('http.host eq "www.jobs.bg"')
    expect(body.violation).toBe('Attack signature detected')
    expect(body.requestHost).toBe('www.jobs.bg')
    expect(body.f5Verdict).toBe('blocked')
    expect(body.timeRange).toEqual({ from: range.from, to: range.to })
  })

  it('does not send an empty expression', async () => {
    const view = render()
    await view.find('textarea').setValue('   ')
    await view
      .findAll('button')
      .find((b) => b.text().includes('Test'))
      ?.trigger('click')

    expect(post).not.toHaveBeenCalled()
  })
})
