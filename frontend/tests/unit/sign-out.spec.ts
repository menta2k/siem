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

/** Signs a store in through the real two-step flow, so state matches production. */
async function signIn(auth: ReturnType<typeof useAuthStore>): Promise<void> {
  post.mockResolvedValueOnce({ data: { mfaChallengeToken: 'challenge' } })
  await auth.login('a@example.com', 'passphrase')

  post.mockResolvedValueOnce({
    data: { accessToken: 'access', refreshToken: 'refresh', user: profile },
  })
  await auth.verifyMfa('123456')
}

beforeEach(() => {
  setActivePinia(createPinia())
  post.mockReset()
})

describe('sign out', () => {
  // THE BUG THIS CATCHES, reported as "SIGN OUT NOT WORKING". /auth/logout is not a
  // public operation — it requires a bearer token. logout() used to call reset() FIRST,
  // which cleared the access token, so the request went out unauthenticated and came
  // back 401 without ever reaching the handler. The refresh token was never revoked and
  // its httpOnly cookie never cleared; the router guard then called restore(), the live
  // cookie minted a fresh session, and the user was bounced straight back into the app.
  //
  // Asserting on ORDER is the point. A test that only checked "logout was called" passed
  // against the broken code.
  it('revokes before clearing local state, so the call carries a token', async () => {
    const auth = useAuthStore()
    await signIn(auth)
    expect(auth.accessToken).toBe('access')

    let tokenAtRequestTime: string | null = null
    post.mockImplementationOnce(() => {
      // Captured mid-flight: this is what the request middleware would read.
      tokenAtRequestTime = auth.accessToken
      return Promise.resolve({ data: {} })
    })

    await auth.logout()

    expect(tokenAtRequestTime).toBe('access')
    expect(auth.accessToken).toBeNull()
    expect(auth.isAuthenticated).toBe(false)
  })

  it('sends the refresh token it holds', async () => {
    const auth = useAuthStore()
    await signIn(auth)

    post.mockResolvedValueOnce({ data: {} })
    await auth.logout()

    expect(post).toHaveBeenLastCalledWith('/api/v1/auth/logout', {
      body: { refreshToken: 'refresh' },
    })
  })

  // A session restored from a cookie alone has no in-memory refresh token. The old code
  // returned early in that case and never called the server at all, leaving the cookie
  // live. The server prefers the cookie anyway, so an empty body still revokes.
  it('still calls the server when only a cookie backs the session', async () => {
    post.mockResolvedValueOnce({ data: { accessToken: 'fresh', user: profile } })
    const auth = useAuthStore()
    await auth.restore()

    post.mockResolvedValueOnce({ data: {} })
    await auth.logout()

    expect(post).toHaveBeenLastCalledWith('/api/v1/auth/logout', { body: {} })
  })

  // The second half of the fix. Even with the ordering corrected, a revocation that
  // fails outright leaves a usable cookie behind — and the router guard calls restore()
  // on the very next navigation. Without the latch that cookie signs the user straight
  // back in, which is the same visible failure by a different route.
  it('stays signed out when revocation fails and a live cookie remains', async () => {
    const auth = useAuthStore()
    await signIn(auth)

    post.mockRejectedValueOnce(new Error('network down'))
    await auth.logout()
    expect(auth.isAuthenticated).toBe(false)

    // The cookie would still work — the server would happily mint a session.
    post.mockResolvedValue({ data: { accessToken: 'resurrected', user: profile } })

    await expect(auth.restore()).resolves.toBe(false)
    expect(auth.isAuthenticated).toBe(false)
    expect(post).toHaveBeenCalledTimes(3) // login, mfa, logout — no refresh attempt
  })

  // The latch must not outlive the sign-out it belongs to, or the next person to use
  // this browser cannot have their session restored after a reload.
  it('restores again after a fresh sign-in', async () => {
    const auth = useAuthStore()
    await signIn(auth)

    post.mockResolvedValueOnce({ data: {} })
    await auth.logout()

    await signIn(auth)
    auth.reset()

    post.mockResolvedValueOnce({ data: { accessToken: 'fresh', user: profile } })
    await expect(auth.restore()).resolves.toBe(true)
  })
})
