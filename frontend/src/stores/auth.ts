import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { api, ApiRequestError, configureAuth } from '@/api/client'

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
 * Tokens live in memory only, never in localStorage: a token in localStorage is
 * readable by any script that gets injected, and this console renders attacker-
 * controlled log content. The cost is a re-login on hard refresh, which is the right
 * trade for a security tool.
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
    search: role.value !== null && role.value !== 'ingest_only',
  }))

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
    user.value = {
      userId: data.user.userId ?? '',
      email: data.user.email ?? '',
      role: (data.user.role ?? 'analyst') as Role,
      tenantId: data.user.tenantId ?? '',
      tenantName: data.user.tenantName ?? '',
      mfaEnabled: data.user.mfaEnabled ?? false,
    }
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

  /** Exchanges the refresh token. Returns false when the session is truly over. */
  async function refresh(): Promise<boolean> {
    if (!refreshToken.value) return false
    try {
      const { data } = await api.POST('/api/v1/auth/refresh', {
        body: { refreshToken: refreshToken.value },
      })
      if (!data?.accessToken) return false
      accessToken.value = data.accessToken
      refreshToken.value = data.refreshToken ?? null
      return true
    } catch (err) {
      if (err instanceof ApiRequestError && err.isAuthFailure) reset()
      return false
    }
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
    reset,
  }
})
