import { afterEach, describe, expect, it, vi } from 'vitest'

import { __traceId as traceId } from '@/api/client'

const UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('traceId', () => {
  it('uses crypto.randomUUID when the page is in a secure context', () => {
    const randomUUID = vi.fn(() => '11111111-2222-4333-8444-555555555555')
    vi.stubGlobal('crypto', { randomUUID, getRandomValues: globalThis.crypto.getRandomValues })

    expect(traceId()).toBe('11111111-2222-4333-8444-555555555555')
    expect(randomUUID).toHaveBeenCalledOnce()
  })

  // THE REGRESSION TEST. crypto.randomUUID is secure-context only, so over plain HTTP
  // on anything but localhost it is undefined. This runs in the request middleware, so
  // a throw here takes down EVERY api call — including login, which is how it was
  // found: the deployed console could not sign anybody in at all.
  it('still produces a v4 uuid when randomUUID is unavailable', () => {
    vi.stubGlobal('crypto', { getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto) })

    const id = traceId()
    expect(id).toMatch(UUID_V4)
  })

  it('falls back again when there is no Web Crypto at all', () => {
    vi.stubGlobal('crypto', undefined)

    expect(traceId()).toMatch(UUID_V4)
  })

  it('does not repeat itself', () => {
    vi.stubGlobal('crypto', { getRandomValues: globalThis.crypto.getRandomValues.bind(globalThis.crypto) })

    const ids = new Set(Array.from({ length: 500 }, () => traceId()))
    expect(ids.size).toBe(500)
  })
})
