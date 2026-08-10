import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, ApiRequestError, configureAuth } from '@/api/client'
import type { components } from '@/api/schema'

type TokenResponse = components['schemas']['TokenResponse']

export type Role = 'admin' | 'analyst' | 'auditor' | 'ingest_only'

export interface UserProfile {
  userId: string
  email: string
  role: Role
  tenantId: string
  tenantName: string
  mfaEnabled: boolean
}

/**
 * Authentication state.
 *
 * The ACCESS token lives in memory only, never in localStorage: a token there is
 * readable by any script that gets injected, and this console renders attacker-
 * controlled log content.
 *
 * That used to cost a re-login on every hard refresh, because the refresh token was held
 * the same way and died with the page too. It now lives in an httpOnly cookie the server
 * sets — out of reach of JavaScript, so the security position is unchanged — and
 * `restore()` exchanges it for a fresh access token on load. The long-lived credential is
 * the one that must never be script-readable; keeping it in a cookie is strictly safer
 * than the localStorage alternative, not a relaxation.
 */
export const useAuthStore = defineStore('auth', () => {
  const accessToken = ref<string | null>(null)
  const refreshToken = ref<string | null>(null)
  const user = ref<UserProfile | null>(null)
  const mfaChallengeToken = ref<string | null>(null)
  const mfaProvisioningUri = ref<string | null>(null)

  const isAuthenticated = computed(() => accessToken.value !== null && user.value !== null)
  const awaitingMfa = computed(() => mfaChallengeToken.value !== null)
  const role = computed<Role | null>(() => user.value?.role ?? null)

  /**
   * Client-side permission hint for hiding controls the user cannot use.
   *
   * This is a UX affordance ONLY. Every one of these actions is independently
   * enforced server-side; hiding a button is not a security boundary.
   */
  const can = computed(() => ({
    manageFeeds: role.value === 'admin',
    manageUsers: role.value === 'admin',
    manageRules: role.value === 'admin',
    changeSettings: role.value === 'admin',
    triageAlerts: role.value === 'admin' || role.value === 'analyst',
    export: role.value === 'admin' || role.value === 'analyst',
    readAudit: role.value === 'admin' || role.value === 'auditor',
    // Storage headroom describes the cluster's disk, which is shared by every tenant on
    // it. Admin-only server-side; this only keeps a panel that would 403 off the page.
    viewStorage: role.value === 'admin',
    search: role.value !== null && role.value !== 'ingest_only',
  }))

  /**
   * Narrows the wire profile to the store's shape.
   *
   * Every field is optional over the wire — protobuf's JSON mapping omits zero values —
   * while the store needs them present. Shared by sign-in and session restore so the two
   * paths cannot disagree about what a user is.
   */
  function toProfile(profile: NonNullable<TokenResponse['user']>): UserProfile {
    return {
      userId: profile.userId ?? '',
      email: profile.email ?? '',
      role: (profile.role ?? 'analyst') as Role,
      tenantId: profile.tenantId ?? '',
      tenantName: profile.tenantName ?? '',
      mfaEnabled: profile.mfaEnabled ?? false,
    }
  }

  function reset(): void {
    accessToken.value = null
    refreshToken.value = null
    user.value = null
    mfaChallengeToken.value = null
    mfaProvisioningUri.value = null
  }

  /** Step 1: password. Returns nothing usable until MFA completes. */
  async function login(email: string, password: string): Promise<void> {
    const { data } = await api.POST('/api/v1/auth/login', { body: { email, password } })
    if (!data) throw new Error('The sign-in response was empty')

    mfaChallengeToken.value = data.mfaChallengeToken ?? null
    mfaProvisioningUri.value = data.mfaEnrolmentRequired ? (data.mfaProvisioningUri ?? null) : null
  }

  /** Step 2: TOTP code. Only here does an access token come into existence. */
  async function verifyMfa(code: string): Promise<void> {
    if (!mfaChallengeToken.value) throw new Error('Sign in again to continue')

    const { data } = await api.POST('/api/v1/auth/mfa', {
      body: { mfaChallengeToken: mfaChallengeToken.value, code },
    })
    if (!data?.accessToken || !data.user) throw new Error('The sign-in response was incomplete')

    accessToken.value = data.accessToken
    refreshToken.value = data.refreshToken ?? null
    user.value = toProfile(data.user)
    mfaChallengeToken.value = null
    mfaProvisioningUri.value = null
  }

  async function logout(): Promise<void> {
    const token = refreshToken.value
    reset()
    if (!token) return
    try {
      await api.POST('/api/v1/auth/logout', { body: { refreshToken: token } })
    } catch {
      // Local state is already cleared, so the user is signed out regardless. A
      // failed server-side revocation must not leave them stuck on a logout screen.
    }
  }

  /**
   * Exchanges the refresh token. Returns false when the session is truly over.
   *
   * Deliberately attempted even with no in-memory refresh token: the server also holds
   * it in an httpOnly cookie the browser sends automatically, and after a page reload
   * that cookie is the ONLY surviving credential. Returning early when the ref is empty
   * is what used to make a refresh look like a signed-out session.
   */
  async function refresh(): Promise<boolean> {
    try {
      const { data } = await api.POST('/api/v1/auth/refresh', {
        // Sent when known; the cookie is what carries it after a reload. The server
        // prefers the cookie and falls back to this.
        body: refreshToken.value ? { refreshToken: refreshToken.value } : {},
      })
      if (!data?.accessToken || !data.user) return false
      accessToken.value = data.accessToken
      refreshToken.value = data.refreshToken ?? null
      // Re-established from the response, not assumed: after a reload there is no
      // in-memory profile, and isAuthenticated requires one.
      user.value = toProfile(data.user)
      return true
    } catch (err) {
      if (err instanceof ApiRequestError && err.isAuthFailure) reset()
      return false
    }
  }

  /**
   * Restores a session on page load, once.
   *
   * The access token lives in memory and dies with the page, so without this every
   * browser refresh looked like a sign-out — the single most jarring thing the console
   * did. The refresh token survives in an httpOnly cookie, so one silent exchange puts
   * the session back.
   *
   * The promise is cached because the router guard and the app shell can both trigger it
   * on the same load, and two concurrent exchanges would have the second present a token
   * the first had already revoked by rotation.
   */
  let restoring: Promise<boolean> | null = null
  async function restore(): Promise<boolean> {
    if (isAuthenticated.value) return true
    restoring ??= refresh().finally(() => {
      restoring = null
    })
    return restoring
  }

  // Wired here rather than in client.ts to keep the module graph acyclic.
  configureAuth(
    () => accessToken.value,
    () => reset(),
  )

  return {
    accessToken,
    user,
    isAuthenticated,
    awaitingMfa,
    mfaProvisioningUri,
    role,
    can,
    login,
    verifyMfa,
    logout,
    refresh,
    restore,
    reset,
  }
})
