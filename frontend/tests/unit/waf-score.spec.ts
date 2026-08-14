import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

import WafScore from '@/components/WafScore.vue'

const vuetify = createVuetify({ components, directives })

function render(waf: Record<string, unknown>) {
  return mount(WafScore, { props: { waf }, global: { plugins: [vuetify] } })
}

describe('WafScore', () => {
  // THE WHOLE REASON THIS COMPONENT EXISTS. Cloudflare's scale runs the opposite way to
  // every other score in the console: 1 is certainly an attack, 100 certainly clean. A
  // bare number invites exactly the wrong reading, so the word travels with it.
  it('calls a low score an attack and a high score clean', () => {
    // A real SQL injection from production: overall 2, driven by the SQLi sub-score.
    const attack = render({ attackScore: 2, sqliScore: 4, xssScore: 98, rceScore: 98 })
    expect(attack.text()).toContain('2/100')
    expect(attack.text()).toContain('attack')
    expect(attack.html()).toContain('text-error')

    // A rule that fires on traffic the ML considers clean — the false-positive shape.
    const clean = render({ attackScore: 86 })
    expect(clean.text()).toContain('86/100')
    expect(clean.text()).toContain('clean')
    expect(clean.html()).toContain('text-success')
  })

  // 0 is not a score, it means the request was never scored. Rendering it would put the
  // most alarming value on this scale against every unscored request.
  it('shows no score when the request was not scored', () => {
    expect(render({ attackScore: 0, action: 'allow' }).text()).not.toContain('/100')
  })

  // 100 is the most common value in real traffic and it IS a score. Treating it as
  // out of range dropped a third of all requests out of the profile in production.
  it('renders the cleanest possible score rather than hiding it', () => {
    const wrapper = render({ attackScore: 100 })

    expect(wrapper.text()).toContain('100/100')
    expect(wrapper.text()).toContain('clean')
  })

  // The overall score is driven by whichever class fired. Listing all three buries it:
  // a SQLi detection reads 4 for SQLi and 98 for XSS and RCE, and the 98s are noise.
  it('names only the sub-score that drove the verdict', () => {
    const text = render({ attackScore: 2, sqliScore: 4, xssScore: 98, rceScore: 98 }).text()

    expect(text).toContain('SQLi 4')
    expect(text).not.toContain('XSS 98')
    expect(text).not.toContain('RCE 98')
  })

  // `log` is the state ruleset tuning acts on: matched, deliberately not enforced.
  it('marks a logged detection as the one needing attention', () => {
    const wrapper = render({ attackScore: 2, action: 'log', source: 'firewallManaged' })

    expect(wrapper.text()).toContain('log')
    expect(wrapper.text()).toContain('firewallManaged')
    expect(wrapper.html()).toContain('text-warning')
  })
})
