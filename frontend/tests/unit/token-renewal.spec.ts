import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiRequestError, configureAuth } from '@/api/client'

/**
 * THE BUG THESE COVER. An access token lasts 15 minutes and the refresh cookie lasts a
 * week, but nothing except the page-load restore() ever spent that cookie. Leaving a tab
 * idle past the access token's lifetime therefore turned the next call into "the access
 * token is not valid" and tore the session down — while a manual browser refresh, the one
 * path that did exchange the cookie, fixed it every time.
 */

/**
 * Per-request overrides.
 *
 * openapi-fetch builds the final URL with `new URL(...)`, which a relative baseUrl only
 * satisfies inside a real browser, and it binds globalThis.fetch when the client is
 * created — before any stub here exists. The replay path inside the client goes through
 * the stubbed global, so both land on the same spy.
 */
function local(): { baseUrl: string; fetch: typeof fetch } {
  return { baseUrl: 'http://localhost', fetch: fetchMock as unknown as typeof fetch }
}

const unauthorized = { code: 'UNAUTHENTICATED', message: 'the access token is not valid' }

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

let token: string | null
let onUnauthorized: ReturnType<typeof vi.fn>
let refresher: ReturnType<typeof vi.fn>
let fetchMock: ReturnType<typeof vi.fn>

/** Records what each attempt actually carried on the wire. */
async function attempts(): Promise<Array<{ url: string; auth: string | null; body: string }>> {
  return Promise.all(
    fetchMock.mock.calls.map(async (call: unknown[]) => {
      const request = call[0] as Request
      return {
        url: request.url,
        auth: request.headers.get('Authorization'),
        body: request.body ? await request.clone().text() : '',
      }
    }),
  )
}

beforeEach(() => {
  token = 'stale'
  onUnauthorized = vi.fn(() => {
    token = null
  })
  // Stands in for the store's exchange: succeeds and leaves a usable token behind.
  refresher = vi.fn(async () => {
    token = 'fresh'
    return true
  })
  configureAuth(
    () => token,
    () => onUnauthorized(),
    () => refresher(),
  )

  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})

describe('silent access-token renewal', () => {
  it('renews and replays a request that expired mid-session', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(401, unauthorized))
      .mockResolvedValueOnce(jsonResponse(200, { alerts: [] }))

    const { data } = await api.GET('/api/v1/alerts', local())

    expect(data).toEqual({ alerts: [] })
    expect(refresher).toHaveBeenCalledTimes(1)
    // The session survives: the user is never bounced back to the login screen.
    expect(onUnauthorized).not.toHaveBeenCalled()

    const sent = await attempts()
    expect(sent).toHaveLength(2)
    expect(sent[0]?.auth).toBe('Bearer stale')
    expect(sent[1]?.auth).toBe('Bearer fresh')
  })

  // The replay is built from a clone taken BEFORE dispatch. Cloning afterwards would
  // throw, because fetch has locked the body stream — so a search, the very thing an
  // idle analyst comes back to, would be the one call that could not be retried.
  it('replays a POST body intact', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse(401, unauthorized))
      .mockResolvedValueOnce(jsonResponse(200, { events: [] }))

    const body = { filters: { clientIp: '203.0.113.7' }, page: { limit: 50 } }
    const { data } = await api.POST('/api/v1/search/events', { body, ...local() })

    expect(data).toEqual({ events: [] })
    const sent = await attempts()
    expect(JSON.parse(sent[1]?.body ?? '{}')).toEqual(body)
  })

  it('surfaces the failure when the refresh cookie is finished too', async () => {
    refresher.mockResolvedValue(false)
    fetchMock.mockResolvedValue(jsonResponse(401, unauthorized))

    await expect(api.GET('/api/v1/alerts', local())).rejects.toBeInstanceOf(ApiRequestError)
    // Only now is the session genuinely over.
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('gives up after one replay rather than looping', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401, unauthorized))

    await expect(api.GET('/api/v1/alerts', local())).rejects.toBeInstanceOf(ApiRequestError)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(refresher).toHaveBeenCalledTimes(1)
    expect(onUnauthorized).toHaveBeenCalledTimes(1)
  })

  // /auth/refresh answering 401 means the refresh credential itself is finished.
  // Renewing on that would recurse; and doing it for /auth/logout would hand a new
  // session to someone on their way out.
  it('never renews on the auth routes themselves', async () => {
    fetchMock.mockResolvedValue(jsonResponse(401, unauthorized))

    await expect(api.POST('/api/v1/auth/refresh', { body: {}, ...local() })).rejects.toBeInstanceOf(
      ApiRequestError,
    )
    expect(refresher).not.toHaveBeenCalled()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  // A 401 is the expiry signal; a 403 is a policy decision that a new token will not
  // change, and replaying it would double every denied request.
  it('does not renew on a permission denial', async () => {
    fetchMock.mockResolvedValue(jsonResponse(403, { code: 'PERMISSION_DENIED', message: 'no' }))

    await expect(api.GET('/api/v1/alerts', local())).rejects.toBeInstanceOf(ApiRequestError)
    expect(refresher).not.toHaveBeenCalled()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  // A dashboard fires several calls at once, so they expire together. Each must be
  // replayed; deduplicating the exchange itself is the store's job.
  it('replays every request when a page full of them expires at once', async () => {
    fetchMock.mockImplementation(async (request: Request) =>
      request.headers.get('Authorization') === 'Bearer fresh'
        ? jsonResponse(200, { alerts: [] })
        : jsonResponse(401, unauthorized),
    )

    const results = await Promise.all([
      api.GET('/api/v1/alerts', local()),
      api.GET('/api/v1/alerts', local()),
      api.GET('/api/v1/alerts', local()),
    ])

    expect(results.every((r) => r.data !== undefined)).toBe(true)
    expect(onUnauthorized).not.toHaveBeenCalled()
  })
})
