import { expect, test, type Page, type Route } from '@playwright/test'
import { visitAsAnalyst } from './support/session'

/**
 * XSS containment — RELEASE BLOCKER (FR-027).
 *
 * This console renders log content, and log content is attacker-controlled by
 * definition: anyone who can send a request to a customer's site can put a payload in
 * a User-Agent header. The defender reading that header back is the target.
 *
 * The test drives the real UI against a stubbed API rather than a seeded backend. That
 * is deliberate: the question is what the BROWSER does with hostile bytes, and a stub
 * lets the payload be exactly hostile rather than whatever survived normalization.
 */

/**
 * The script-tag payload, named because the assertions look for it by sight: it is
 * what proves the page rendered the hostile string as TEXT rather than dropping it.
 */
const SCRIPT_PAYLOAD = '<script>window.__xss = true</script>'

/** Payloads chosen for the distinct sinks they exploit, not for variety. */
const PAYLOADS = [
  SCRIPT_PAYLOAD,
  '<img src=x onerror="window.__xss = true">',
  '"><svg onload="window.__xss = true">',
  `<iframe srcdoc="<script>parent.__xss = true</script>">`,
  'javascript:window.__xss=true',
  '<a href="javascript:window.__xss=true">click</a>',
  '{{constructor.constructor("window.__xss = true")()}}',
]

function eventWith(payload: string, index: number) {
  return {
    eventId: `evt-${index}`,
    eventTime: '2026-08-06T12:00:00Z',
    vendor: 'VENDOR_CLOUDFLARE',
    feedId: '00000000-0000-4000-8000-0000000000bb',
    vendorRequestId: payload,
    client: {
      ip: '203.0.113.10',
      ipShared: false,
      asn: 64512,
      country: payload,
      userAgent: payload,
    },
    request: {
      host: payload,
      path: `/checkout${payload}`,
      query: payload,
      method: 'GET',
      status: 200,
    },
    verdict: 'VERDICT_BLOCKED',
    verdictReason: payload,
    ruleId: payload,
    ruleIds: [payload],
    score: 0.9,
    scoreKind: 'bot',
    unknownFields: [payload],
  }
}

/** Stubs auth and search so the UI renders the payloads without a live backend. */
async function stubApi(page: Page): Promise<void> {
    await page.route('**/api/v1/search/events', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        items: PAYLOADS.map(eventWith),
        page: { nextCursor: '', total: PAYLOADS.length, totalIsEstimate: false },
      }),
    }),
  )

  await page.route('**/api/v1/events/**', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        summary: eventWith(SCRIPT_PAYLOAD, 0),
        rawPayload: JSON.stringify({ userAgent: SCRIPT_PAYLOAD }),
        rawContentType: 'application/json',
        rawExtra: { evil: SCRIPT_PAYLOAD },
        correlationId: '',
      }),
    }),
  )
}

test.describe('XSS containment', () => {
  test.beforeEach(async ({ page }) => {
    await stubApi(page)

    // Any dialog at all is a failure: alert/confirm/prompt are the classic proof that
    // injected script executed. Accepting it silently would let the test pass.
    page.on('dialog', async (dialog) => {
      await dialog.dismiss()
      throw new Error(`a dialog was opened by injected content: ${dialog.message()}`)
    })
  })

  test('log content renders as literal text and executes nothing', async ({ page }) => {
    const consoleErrors: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text())
    })

    await visitAsAnalyst(page, '/search?from=2026-08-06T11:00:00Z&to=2026-08-06T12:00:00Z')

    // The payload must appear as TEXT somewhere on the page. If it does not appear at
    // all the test proves nothing — it would pass just as happily against a blank page.
    const body = page.locator('body')
    await expect(body).toContainText('<script>', { timeout: 10_000 })

    // No payload executed.
    const executed = await page.evaluate(() => '__xss' in window)
    expect(executed, 'an injected payload executed').toBe(false)

    // No element was actually created from the markup: finding a real <img> or <svg>
    // with the payload's handler means the string was parsed as HTML, not escaped.
    const injectedElements = await page.evaluate(() => {
      const suspicious = document.querySelectorAll(
        'img[onerror], svg[onload], iframe[srcdoc], a[href^="javascript:"]',
      )
      return suspicious.length
    })
    expect(injectedElements, 'markup from log content was parsed as HTML').toBe(0)

    // A real CSP violation is reported by Chrome as "Refused to ...". Matching on
    // that rather than on the words "Content Security Policy" matters: the latter also
    // matches advisory messages about the policy itself, and a test that fails on
    // advice gets muted rather than read.
    //
    // Failing on a genuine violation is deliberate even though the payload was blocked:
    // it means the ESCAPING did not hold and only the second line of defence saved us.
    const cspViolations = consoleErrors.filter((text) => text.startsWith('Refused to'))
    expect(cspViolations, `CSP violations: ${cspViolations.join('; ')}`).toHaveLength(0)
  })

  test('the raw payload view escapes its content', async ({ page }) => {
    await visitAsAnalyst(page, '/search?from=2026-08-06T11:00:00Z&to=2026-08-06T12:00:00Z')

    const firstRow = page.locator('tbody tr').first()
    await firstRow.click()

    // The raw vendor payload is the most dangerous view in the product: it exists to
    // show exactly what arrived, so it cannot sanitise, only escape.
    const raw = page.locator('.raw-payload')
    await expect(raw).toBeVisible({ timeout: 10_000 })
    await expect(raw).toContainText('<script>')

    const executed = await page.evaluate(() => '__xss' in window)
    expect(executed, 'the raw payload view executed injected script').toBe(false)
  })

  test('no component uses v-html on log content', async ({ page }) => {
    await visitAsAnalyst(page, '/search?from=2026-08-06T11:00:00Z&to=2026-08-06T12:00:00Z')

    // Belt and braces against the escaping being bypassed somewhere: if any log field
    // had been rendered with v-html, the payload would exist in the DOM as elements
    // rather than as text.
    const scriptCount = await page.evaluate(
      () => document.querySelectorAll('body script:not([src])').length,
    )
    expect(scriptCount, 'inline scripts were injected into the body').toBe(0)
  })
})
