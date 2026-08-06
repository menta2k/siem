import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as vuetifyComponents from 'vuetify/components'
import * as vuetifyDirectives from 'vuetify/directives'
import VendorVerdictBadge from '@/components/VendorVerdictBadge.vue'

const vuetify = createVuetify({
  components: vuetifyComponents,
  directives: vuetifyDirectives,
})

function render(props: Record<string, unknown>) {
  return mount(VendorVerdictBadge, {
    props,
    global: { plugins: [vuetify] },
  })
}

describe('VendorVerdictBadge', () => {
  it('names the vendor and its verdict', () => {
    const badge = render({ vendor: 'VENDOR_CLOUDFLARE', verdict: 'VERDICT_BLOCKED' })
    expect(badge.text()).toContain('Cloudflare')
    expect(badge.text()).toContain('Blocked')
  })

  // A vendor in monitoring mode did not decide to permit the request — it decided not
  // to act. Presenting the two alike would let "everyone allowed it" hide a vendor
  // that was never enforcing at all.
  it('distinguishes monitored from allowed', () => {
    const monitored = render({ vendor: 'VENDOR_F5', verdict: 'VERDICT_MONITORED' })
    const allowed = render({ vendor: 'VENDOR_F5', verdict: 'VERDICT_ALLOWED' })

    expect(monitored.text()).toContain('Monitored')
    expect(monitored.text()).not.toContain('Allowed')
    expect(allowed.text()).toContain('Allowed')
  })

  // Colour is the one channel a colour-blind analyst cannot rely on, and this is the
  // most decision-relevant fact on the card.
  it('marks disagreement with text and an icon, not colour alone', () => {
    const badge = render({
      vendor: 'VENDOR_F5',
      verdict: 'VERDICT_BLOCKED',
      disagreeing: true,
    })
    expect(badge.text()).toContain('Disagrees')
    expect(badge.find('[aria-label*="disagrees"]').exists()).toBe(true)
    expect(badge.find('.vendor-verdict--disagreeing').exists()).toBe(true)
  })

  it('shows no disagreement marker when the vendors agreed', () => {
    const badge = render({ vendor: 'VENDOR_F5', verdict: 'VERDICT_ALLOWED' })
    expect(badge.text()).not.toContain('Disagrees')
    expect(badge.find('.vendor-verdict--disagreeing').exists()).toBe(false)
  })

  it('shows the rule and score when the vendor supplied them', () => {
    const badge = render({
      vendor: 'VENDOR_CLOUDFLARE',
      verdict: 'VERDICT_ALLOWED',
      ruleId: 'prod_waf_policy',
      score: 0.91,
    })
    expect(badge.text()).toContain('prod_waf_policy')
    expect(badge.text()).toContain('0.91')
  })

  // An absent score is not a zero score. Rendering 0.00 for a vendor that does not
  // score requests would read as "certainly human" — the opposite of "no opinion".
  it('omits the score when the vendor does not score requests', () => {
    const badge = render({ vendor: 'VENDOR_F5', verdict: 'VERDICT_BLOCKED' })
    expect(badge.text()).not.toContain('Score')
  })

  it('says the verdict was not reported rather than inventing one', () => {
    const badge = render({ vendor: 'VENDOR_DATADOME' })
    expect(badge.text()).toContain('Not reported')
  })
})
