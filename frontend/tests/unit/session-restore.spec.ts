import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'

const post = vi.fn()
vi.mock('@/api/client', () => ({
  api: { POST: (...args: unknown[]) => post(...args) },
  ApiRequestError: class extends Error {
    isAuthFailure = true
  },
  configureAuth: () => {},
}))

import { useAuthStore } from '@/stores/auth'

const profile = {
  userId: 'u1',
  email: 'a@example.com',
  role: 'analyst',
  tenantId: 't1',
  tenantName: 'acme',
  mfaEnabled: true,
}

beforeEach(() => {
  setActivePinia(createPinia())
  post.mockReset()
})

describe('session restore', () => {
  // THE BUG THIS FIXES. A page reload discards the in-memory access token AND the
  // in-memory refresh token, so the old code returned early and every browser refresh
  // looked like a signed-out session. The refresh token now survives in an httpOnly
  // cookie the browser sends automatically — so the exchange must be attempted even
  // with nothing in memory.
  it('restores a session with no in-memory token, using the cookie', async () => {
    post.mockResolvedValue({ data: { accessToken: 'fresh', user: profile } })

    const auth = useAuthStore()
    expect(auth.isAuthenticated).toBe(false)

    await expect(auth.restore()).resolves.toBe(true)
    expect(auth.isAuthenticated).toBe(true)
    expect(post).toHaveBeenCalledWith('/api/v1/auth/refresh', { body: {} })
  })

  // isAuthenticated needs BOTH a token and a profile. Restoring only the token would
  // leave the guard rejecting a session that actually succeeded.
  it('re-establishes the user profile, not just the token', async () => {
    post.mockResolvedValue({ data: { accessToken: 'fresh', user: profile } })

    const auth = useAuthStore()
    await auth.restore()

    expect(auth.user?.email).toBe('a@example.com')
    expect(auth.role).toBe('analyst')
  })

  // Two concurrent exchanges would have the second present a token the first already
  // revoked by rotation — logging the user out during the very act of restoring them.
  it('exchanges only once when called concurrently', async () => {
    post.mockResolvedValue({ data: { accessToken: 'fresh', user: profile } })

    const auth = useAuthStore()
    await Promise.all([auth.restore(), auth.restore(), auth.restore()])

    expect(post).toHaveBeenCalledTimes(1)
  })

  // Every 401 on a page full of parallel requests now asks for a renewal, so the
  // deduplication has to hold for refresh() itself and not just for the page-load path.
  // Rotation makes a second concurrent exchange present an already-burned token, which
  // would end the session the renewal was called to save.
  it('exchanges only once when refreshed concurrently', async () => {
    post.mockResolvedValue({ data: { accessToken: 'fresh', user: profile } })

    const auth = useAuthStore()
    const results = await Promise.all([auth.refresh(), auth.refresh(), auth.refresh()])

    expect(results).toEqual([true, true, true])
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('does not exchange when already signed in', async () => {
    post.mockResolvedValue({ data: { accessToken: 'fresh', user: profile } })

    const auth = useAuthStore()
    await auth.restore()
    post.mockClear()

    await auth.restore()
    expect(post).not.toHaveBeenCalled()
  })

  // A genuinely expired session must resolve false rather than hang or throw, or the
  // router guard never completes and the app renders nothing at all.
  it('reports failure when the cookie is missing or expired', async () => {
    post.mockRejectedValue(new Error('unauthenticated'))

    const auth = useAuthStore()
    await expect(auth.restore()).resolves.toBe(false)
    expect(auth.isAuthenticated).toBe(false)
  })

  it('reports failure on an incomplete response', async () => {
    post.mockResolvedValue({ data: { accessToken: 'fresh' } })

    const auth = useAuthStore()
    await expect(auth.restore()).resolves.toBe(false)
    expect(auth.isAuthenticated).toBe(false)
  })

  // A second attempt after a failure must actually retry, not return the cached
  // rejection for the rest of the page's life.
  it('retries after a failed restore', async () => {
    post.mockRejectedValueOnce(new Error('unauthenticated'))
    const auth = useAuthStore()
    await auth.restore()

    post.mockResolvedValue({ data: { accessToken: 'fresh', user: profile } })
    await expect(auth.restore()).resolves.toBe(true)
  })
})
