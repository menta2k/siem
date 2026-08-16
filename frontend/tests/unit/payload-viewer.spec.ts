import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'

import PayloadViewer from '@/components/PayloadViewer.vue'

const vuetify = createVuetify({ components, directives })

const F5 =
  '<130>Aug 16 08:52:52 saruman.ipmi.verax.net ASM:unit_hostname="saruman.ipmi.verax.net",' +
  'violations="Illegal request length,Illegal file type",request_status="blocked",' +
  'ip_client="104.22.104.225",username="N/A",query_string="",attack_type="Buffer Overflow",' +
  'uri="/status_page.php",' +
  'request="GET /status_page.php HTTP/1.1\\r\\nHost: www.jobs.bg\\r\\n\\r\\n"'

function render(props: Record<string, unknown>) {
  return mount(PayloadViewer, { props, global: { plugins: [vuetify] } })
}

describe('PayloadViewer', () => {
  it('shows a syslog record as named fields', () => {
    const view = render({ raw: F5 })

    expect(view.text()).toContain('request_status')
    expect(view.text()).toContain('blocked')
    expect(view.text()).toContain('104.22.104.225')
    // The envelope is present but kept out of the field list.
    expect(view.text()).toContain('local0.crit (130)')
  })

  // The padding is hidden by default and COUNTED, never dropped silently. A viewer that
  // quietly discards fields is one an analyst cannot trust to be showing everything.
  it('folds empty fields away but says how many', () => {
    const view = render({ raw: F5 })

    expect(view.text()).not.toContain('username')
    expect(view.text()).toContain('empty hidden')
  })

  it('reveals the empty fields on request', async () => {
    const view = render({ raw: F5 })
    await view
      .findAll('button')
      .find((b) => b.text().includes('Show empty'))
      ?.trigger('click')

    expect(view.text()).toContain('username')
  })

  // Fifty fields is too many to scan. Filtering is the difference between finding the
  // one field the event was opened for and reading the whole record.
  it('narrows the fields to a filter', async () => {
    const view = render({ raw: F5 })
    await view.find('input').setValue('ip_client')

    expect(view.text()).toContain('104.22.104.225')
    expect(view.text()).not.toContain('request_status')
  })

  it('says so when a filter matches nothing', async () => {
    const view = render({ raw: F5 })
    await view.find('input').setValue('zzzz')

    expect(view.text()).toContain('No field matches')
  })

  // The formatted view is an interpretation. Evidence has to stay checkable against the
  // bytes the vendor actually sent, so the raw text is always one click away.
  it('shows the payload exactly as received on demand', async () => {
    const view = render({ raw: F5 })
    await view
      .findAll('button')
      .find((b) => b.text() === 'Raw')
      ?.trigger('click')

    expect(view.find('.payload-raw').text()).toBe(F5)
  })

  // This is the field an XSS payload arrives in. It must render as the characters the
  // vendor sent, in the structured view exactly as in the raw one.
  it('renders vendor markup as text, never as markup', () => {
    const view = render({ raw: '{"ua":"<img src=x onerror=alert(1)>","b":"2"}' })

    expect(view.text()).toContain('<img src=x onerror=alert(1)>')
    expect(view.find('img').exists()).toBe(false)
  })

  it('reports an unretained payload plainly', () => {
    expect(render({ raw: '' }).text()).toContain('(not retained)')
  })

  // A payload with no structure to show is still shown. One the console refuses to
  // render is worse than an ugly one.
  it('falls back to the raw block for an unstructured payload', () => {
    const view = render({ raw: 'connection closed by peer' })

    expect(view.find('.payload-raw').text()).toBe('connection closed by peer')
    expect(view.findAll('button').some((b) => b.text() === 'Raw')).toBe(false)
  })
})
