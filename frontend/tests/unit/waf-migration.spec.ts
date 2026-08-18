import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createPinia, setActivePinia } from 'pinia'

import RuleAgreementTable from '@/components/RuleAgreementTable.vue'
import {
  MIGRATION_RANGES,
  DEFAULT_MIGRATION_HOURS,
  useMigrationRange,
} from '@/composables/useMigrationRange'

// The samples component fires its own request on mount; the table under test is what
// matters here, so it is stubbed out.
vi.mock('@/components/MigrationSamples.vue', () => ({
  default: { name: 'MigrationSamples', template: '<div class="samples-stub" />' },
}))

const vuetify = createVuetify({ components, directives })

const range = { from: '2026-08-09T00:00:00Z', to: '2026-08-16T00:00:00Z' }

function rule(overrides: Record<string, unknown> = {}) {
  return {
    ruleId: '23548ee2b36547a1be09bb2c0550c529',
    ruleDescription: 'Block WordPress probes',
    action: 'monitored',
    correlated: '147',
    f5Blocked: '140',
    f5Flagged: '4',
    f5Allowed: '3',
    hosts: '1',
    requestHost: 'jobs.bg',
    reading: 'ready',
    lastSeen: '2026-08-16T00:00:00Z',
    ...overrides,
  }
}

function render(
  rules: ReturnType<typeof rule>[],
  sampleVerdict: 'blocked' | 'allowed' = 'blocked',
  minCorrelated = 10,
) {
  setActivePinia(createPinia())
  return mount(RuleAgreementTable, {
    props: { rules, range, sampleVerdict, minCorrelated },
    global: { plugins: [vuetify] },
  })
}

describe('RuleAgreementTable', () => {
  // THE POINT OF THE WHOLE STAGE. F5 has a transparent mode of its own, so a request it
  // flagged without blocking is weaker evidence than one it stopped and stronger than one
  // it ignored. Merging any two of these counts would make a rule read as ready to
  // enforce, or as a false positive, on evidence that says neither.
  it('shows the three F5 counts separately', () => {
    const view = render([rule()])
    const text = view.text()

    expect(text).toContain('140')
    expect(text).toContain('4')
    expect(text).toContain('3')
    // The denominator: two confirmations out of two is not two out of two hundred.
    expect(text).toContain('147')
  })

  // A 32-character hex id is unreadable in a decision this consequential, but it is also
  // what gets pasted into the Cloudflare dashboard — so both are shown.
  it('names the rule and keeps its id', () => {
    const view = render([rule()])

    expect(view.text()).toContain('Block WordPress probes')
    expect(view.text()).toContain('23548ee2b36547a1be09bb2c0550c529')
  })

  it('falls back to the id alone when the rule cannot be named', () => {
    const view = render([rule({ ruleDescription: '' })])

    expect(view.text()).toContain('23548ee2b36547a1be09bb2c0550c529')
  })

  // THE ONE A RULE'S AUTHOR NOTICES. A rule matching perfectly but under the floor used to
  // read "not enough evidence", which says only that something is missing and never what or
  // how much — its author read it as a criticism of the rule. It is shown as PROGRESS
  // instead, so the bar and the distance to it are both on screen.
  it('shows an unjudged rule as progress towards the bar, not as a verdict', () => {
    const view = render([rule({ reading: 'insufficient', correlated: '8', f5Blocked: '8' })])

    expect(view.text()).toContain('8 of 10 requests')
    expect(view.text()).not.toContain('not enough evidence')
  })

  // The bar comes from the server, which is also where it is applied. A number repeated in
  // the frontend is a number that can drift from the one the query used.
  it('takes the bar from the server rather than assuming it', () => {
    const view = render([rule({ reading: 'insufficient', correlated: '3' })], 'blocked', 25)

    expect(view.text()).toContain('3 of 25 requests')
  })

  // The reading is computed server-side so the stage a rule appears under and the label
  // beside it cannot drift. The component only translates it.
  it('translates every reading the server can send', () => {
    for (const [reading, label] of [
      ['ready', 'ready to enforce'],
      ['disputed', 'needs a look'],
      ['false_positive', 'likely false positive'],
      ['insufficient', 'too few requests yet'],
    ]) {
      expect(render([rule({ reading })]).text()).toContain(label)
    }
  })

  // An unknown reading must not render an empty chip: a blank verdict on this table reads
  // as "no opinion" when it actually means the client is out of date with the server.
  it('degrades to insufficient for a reading it does not know', () => {
    expect(render([rule({ reading: 'something_new' })]).text()).toContain('too few requests yet')
  })

  // Naming one of several hosts would be wrong, so the server sends an empty host and a
  // count instead.
  it('says how many hosts when a rule fires on more than one', () => {
    expect(render([rule({ requestHost: '', hosts: '4' })]).text()).toContain('4 hosts')
  })

  it('opens the requests behind a rule when the row is clicked', async () => {
    const view = render([rule()])
    expect(view.find('.samples-stub').exists()).toBe(false)

    await view.find('tbody tr').trigger('click')
    expect(view.find('.samples-stub').exists()).toBe(true)

    await view.find('tbody tr').trigger('click')
    expect(view.find('.samples-stub').exists()).toBe(false)
  })

  // A rule with no correlated requests would divide by zero and render NaN-wide bars.
  it('survives a rule with nothing correlated', () => {
    const view = render([rule({ correlated: '0', f5Blocked: '0', f5Flagged: '0', f5Allowed: '0' })])

    expect(view.html()).not.toContain('NaN')
  })
})

describe('useMigrationRange', () => {
  // A migration decision is made on accumulated agreement. This deployment sees ~50 F5
  // blocks a day, so an hour of evidence is a handful of requests and cannot support
  // turning a rule on — which is why the DEFAULT is a week even though an hour is
  // offered. The hour is for checking whether a change has taken effect yet.
  it('defaults to a week, whatever else the menu offers', () => {
    const { rangeHours } = useMigrationRange()

    expect(rangeHours.value).toBe(DEFAULT_MIGRATION_HOURS)
    expect(DEFAULT_MIGRATION_HOURS).toBe(168)
    expect(MIGRATION_RANGES.some((r) => r.value === DEFAULT_MIGRATION_HOURS)).toBe(true)
  })

  // Every stage reads the same menu, so an option added here reaches all three pages.
  it('offers an hour through to a month, shortest first', () => {
    expect(MIGRATION_RANGES.map((r) => r.value)).toEqual([1, 24, 72, 168, 720])
  })

  // The host reaches the SERVER. Rows come back ordered by volume, so filtering the
  // response would leave a quiet host crowded out of the limit before the client saw it.
  it('sends the host to the server, trimmed, and omits it when blank', () => {
    const { host, queryParams } = useMigrationRange()

    expect(queryParams()).not.toHaveProperty('requestHost')

    host.value = '  api.jobs.bg  '
    expect(queryParams().requestHost).toBe('api.jobs.bg')

    host.value = '   '
    expect(queryParams()).not.toHaveProperty('requestHost')
  })

  it('spans exactly the selected number of hours', () => {
    const { rangeHours, currentRange } = useMigrationRange()
    rangeHours.value = 72

    const { from, to } = currentRange()
    const hours = (Date.parse(to) - Date.parse(from)) / 3_600_000

    expect(hours).toBeCloseTo(72, 5)
  })
})
