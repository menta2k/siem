import { expect, test, type Page, type Route } from '@playwright/test'
import { visitAsAnalyst } from './support/session'

/**
 * The investigation path an analyst actually walks (quickstart V3):
 *
 *   search → paginate → open a correlated record → export
 *
 * Driven against a stubbed API. The backend's own behaviour is covered by the
 * integration suite; what this test can only check here is that the pieces connect —
 * that the cursor reaches the next request, that a record opens, that an export lands
 * as a file.
 */

const CORRELATION_ID = '6b3f1b6e-9f1a-4f3e-8f0a-5b9c2d1e7a44'

function pageOfEvents(prefix: string, count: number, nextCursor: string) {
  return {
    items: Array.from({ length: count }, (_, i) => ({
      eventId: `${prefix}-${i}`,
      eventTime: '2026-08-06T12:00:00Z',
      vendor: 'VENDOR_CLOUDFLARE',
      client: { ip: '203.0.113.10', country: 'DE' },
      request: { host: 'shop.example.com', path: '/checkout', method: 'GET', status: 200 },
      verdict: 'VERDICT_BLOCKED',
      ruleId: 'waf-sqli',
      score: 0.9,
    })),
    page: { nextCursor, total: count, totalIsEstimate: nextCursor !== '' },
  }
}

async function stubApi(page: Page): Promise<void> {
    // The cursor is what proves paging is wired: the second request must carry the
  // cursor the first response returned, or "load more" silently re-reads page one.
  let searchCalls = 0
  await page.route('**/api/v1/search/events', async (route: Route) => {
    const body = route.request().postDataJSON() as { page?: { cursor?: string } }
    searchCalls += 1

    if (searchCalls === 1) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(pageOfEvents('first', 5, 'cursor-page-2')),
      })
      return
    }

    if (body?.page?.cursor !== 'cursor-page-2') {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({
          code: 'CURSOR_INVALID',
          message: 'the second page did not carry the cursor from the first',
        }),
      })
      return
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(pageOfEvents('second', 3, '')),
    })
  })

  await page.route('**/api/v1/events/**', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        summary: {
          eventId: 'first-0',
          eventTime: '2026-08-06T12:00:00Z',
          vendor: 'VENDOR_CLOUDFLARE',
          client: { ip: '203.0.113.10', userAgent: 'curl/8.0' },
          request: { host: 'shop.example.com', path: '/checkout', method: 'GET' },
          verdict: 'VERDICT_BLOCKED',
        },
        rawPayload: '{"ClientIP":"203.0.113.10"}',
        correlationId: CORRELATION_ID,
      }),
    }),
  )

  await page.route(`**/api/v1/correlated/${CORRELATION_ID}`, (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        correlationId: CORRELATION_ID,
        windowStart: '2026-08-06T12:00:00Z',
        firstEventTime: '2026-08-06T12:00:00Z',
        lastEventTime: '2026-08-06T12:00:02Z',
        client: { ip: '203.0.113.10', ipShared: true, country: 'DE' },
        request: { host: 'shop.example.com', path: '/checkout', method: 'GET' },
        vendorVerdicts: [
          { vendor: 'VENDOR_CLOUDFLARE', verdict: 'VERDICT_ALLOWED', score: 0.2 },
          { vendor: 'VENDOR_F5', verdict: 'VERDICT_BLOCKED', ruleId: 'waf-sqli' },
        ],
        vendorCount: 2,
        eventIds: ['first-0', 'f5-0'],
        combinedOutcome: 'VERDICT_BLOCKED',
        hasDisagreement: true,
        disagreementKind: 'DISAGREEMENT_KIND_ALLOW_VS_BLOCK',
        joinSignals: ['JOIN_SIGNAL_IP_HOST_PATH_METHOD', 'JOIN_SIGNAL_TIME_WINDOW'],
        joinTier: 2,
        confidence: 'CONFIDENCE_LOW',
        candidateCount: 3,
        version: '1',
        amended: false,
      }),
    }),
  )

  await page.route('**/api/v1/search/export', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        // btoa rather than Buffer: the test config has no Node types, and the app
        // decodes with atob, so encoding the same way keeps the stub honest.
        content: btoa('event_id\nfirst-0\n'),
        contentType: 'text/csv; charset=utf-8',
        filename: 'events-20260806T120000Z.csv',
        rowCount: '1',
        truncated: false,
      }),
    }),
  )
}

test.describe('investigation path', () => {
  test.beforeEach(async ({ page }) => {
    await stubApi(page)
  })

  test('search, paginate, open the correlated record, export', async ({ page }) => {
    await visitAsAnalyst(page, '/search?from=2026-08-06T11:00:00Z&to=2026-08-06T12:00:00Z')

    const rows = page.locator('tbody tr')
    await expect(rows).toHaveCount(5, { timeout: 10_000 })

    // Paging APPENDS. Replacing the list would lose what the analyst already read.
    await page.getByRole('button', { name: 'Load more' }).click()
    await expect(rows).toHaveCount(8, { timeout: 10_000 })

    // Drill into an event, then through to its correlated record.
    await rows.first().click()
    await expect(page.locator('.raw-payload')).toBeVisible({ timeout: 10_000 })

    await page.getByRole('link', { name: CORRELATION_ID }).click()
    await expect(page.getByText('Why these events were joined')).toBeVisible({
      timeout: 10_000,
    })

    // The join provenance is the point of the record: an analyst who cannot see why
    // two events were joined cannot act on it.
    // Exact matches: 'Low' is a substring of 'allowed', and the page says both.
    await expect(page.getByText('Disagreement', { exact: true })).toBeVisible()
    await expect(page.getByText('Low', { exact: true })).toBeVisible()
  })

  test('the search is shareable by link', async ({ page }) => {
    await visitAsAnalyst(
      page,
      '/search?from=2026-08-06T11:00:00Z&to=2026-08-06T12:00:00Z&requestHost=shop.example.com',
    )

    // The filter from the URL must be visible in the panel, or a shared link produces
    // results the recipient cannot explain.
    // getByRole rather than getByLabel: the field's clear button is also labelled
    // "Host", so the label alone is ambiguous.
    await expect(page.getByRole('textbox', { name: 'Host' })).toHaveValue(
      'shop.example.com',
      { timeout: 10_000 },
    )
    await expect(page.locator('tbody tr')).toHaveCount(5)
  })

  test('an export downloads as a file', async ({ page }) => {
    await visitAsAnalyst(page, '/search?from=2026-08-06T11:00:00Z&to=2026-08-06T12:00:00Z')

    const downloadPromise = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export' }).click()
    await page.getByRole('listitem').filter({ hasText: 'CSV' }).click()

    const download = await downloadPromise
    expect(download.suggestedFilename()).toMatch(/\.csv$/)
  })
})
