import { expect, type Page, type Route } from '@playwright/test'

/**
 * Test identity. Analyst rather than admin: it is the role that actually investigates,
 * and running the E2E path as an admin would hide a missing analyst permission.
 */
export const TEST_USER = {
  userId: '00000000-0000-4000-8000-000000000001',
  email: 'analyst@example.com',
  role: 'analyst',
  tenantId: '00000000-0000-4000-8000-0000000000aa',
  tenantName: 'acme',
  mfaEnabled: true,
} as const

/**
 * Opens a page as a signed-in analyst.
 *
 * Tokens live in memory only — deliberately, so an injected script cannot read them
 * out of localStorage — and that has a consequence every E2E test has to respect: a
 * full page load DISCARDS the session. Signing in and then calling page.goto() lands
 * back on the login form, which reads as a broken test rather than as the security
 * property it is.
 *
 * So this follows the flow a real user does with a shared link: request the deep link,
 * get bounced to /login with a redirect, sign in, and arrive where they were going.
 * That exercises the guard's redirect handling on every run as a side effect.
 */
export async function visitAsAnalyst(page: Page, path: string): Promise<void> {
  await page.route('**/api/v1/auth/login', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        mfaChallengeToken: 'stub-challenge',
        mfaEnrolmentRequired: false,
      }),
    }),
  )

  await page.route('**/api/v1/auth/mfa', (route: Route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        accessToken: 'stub-access-token',
        refreshToken: 'stub-refresh-token',
        user: TEST_USER,
      }),
    }),
  )

  // The guard redirects to /login?redirect=<path>, and the login form honours it.
  await page.goto(path)
  await expect(page).toHaveURL(/\/login/, { timeout: 15_000 })

  await page.getByLabel('Email').fill(TEST_USER.email)
  await page.getByLabel('Password').fill('correct-horse-battery-staple')
  await page.getByRole('button', { name: 'Continue' }).click()

  await page.getByLabel('Authentication code').fill('123456')
  await page.getByRole('button', { name: 'Sign in' }).click()

  // Waiting on the destination rather than on a timeout is what keeps this from
  // flaking under load, and it asserts the redirect actually carried the user through.
  await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 })
  await page.waitForLoadState('networkidle')
}
