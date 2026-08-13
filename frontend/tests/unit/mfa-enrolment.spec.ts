import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

import MfaEnrolment from '@/components/MfaEnrolment.vue'

const vuetify = createVuetify({ components, directives })

const SECRET = 'JBSWY3DPEHPK3PXP'
const URI = `otpauth://totp/siem:a@example.com?secret=${SECRET}&issuer=siem&algorithm=SHA1&digits=6&period=30`

function render(uri = URI) {
  return mount(MfaEnrolment, { props: { uri }, global: { plugins: [vuetify] } })
}

/** Waits for the QR watcher's promise chain to settle. */
async function settled(wrapper: ReturnType<typeof render>): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
  await wrapper.vm.$nextTick()
}

describe('MFA enrolment', () => {
  it('renders the provisioning URI as a scannable image', async () => {
    const wrapper = render()
    await settled(wrapper)

    const img = wrapper.find('img')
    expect(img.exists()).toBe(true)
    expect(img.attributes('src')).toMatch(/^data:image\/svg\+xml/)
  })

  // THE PROPERTY THAT MATTERS. The QR encodes a live TOTP secret. Generating it through
  // any hosted chart API would hand every user's second factor to a third party, and a
  // remote <img src> would do exactly that. The image must be locally generated, which
  // for a data: URI it provably is.
  it('generates the code locally, never via a remote URL', async () => {
    const wrapper = render()
    await settled(wrapper)

    const src = wrapper.find('img').attributes('src') ?? ''
    expect(src.startsWith('data:')).toBe(true)
    expect(src).not.toMatch(/^https?:/)
  })

  // The secret would otherwise be announced by a screen reader and captured by anything
  // that logs accessibility trees.
  it('keeps the secret out of the alt text', async () => {
    const wrapper = render()
    await settled(wrapper)

    expect(wrapper.find('img').attributes('alt')).not.toContain(SECRET)
  })

  // A user on the same device as the console cannot scan their own screen, and desktop
  // password managers take the bare key. Enrolment must not be scan-only.
  it('offers the bare setup key as a fallback', async () => {
    const wrapper = render()
    await settled(wrapper)

    expect(wrapper.text()).not.toContain(SECRET)

    await wrapper.find('button').trigger('click')
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain(SECRET)
    // The bare key, not the whole otpauth:// string, which no app asks you to type.
    expect(wrapper.text()).not.toContain('otpauth://')
  })

  // A URI with no secret parameter must still let the user enrol by hand rather than
  // rendering an empty box.
  it('falls back to the full URI when no secret parameter is present', async () => {
    const wrapper = render('otpauth://totp/siem:a@example.com')
    await settled(wrapper)

    await wrapper.find('button').trigger('click')
    await wrapper.vm.$nextTick()

    expect(wrapper.text()).toContain('otpauth://totp/siem:a@example.com')
  })
})
