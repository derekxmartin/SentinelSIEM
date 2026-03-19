import { Page, expect } from '@playwright/test'

const API_BASE = 'http://localhost:8081/api/v1'

/**
 * Ensure a test user exists and login via API token injection.
 * Waits for the dashboard sidebar to be fully visible before returning.
 */
export async function loginAsAdmin(page: Page) {
  // Ensure admin user exists via API (idempotent — setup endpoint 409s if already done).
  try {
    const res = await fetch(`${API_BASE}/auth/setup-required`)
    const data = await res.json()
    if (data.setup_required) {
      await fetch(`${API_BASE}/auth/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'e2e_admin',
          password: 'E2eTestPass123!',
          display_name: 'E2E Admin',
          email: 'e2e@akeso.local',
        }),
      })
    }
  } catch {
    // Server may already be set up.
  }

  // Login via API to get tokens, then inject into localStorage.
  const loginRes = await fetch(`${API_BASE}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'e2e_admin', password: 'E2eTestPass123!' }),
  })

  let loginData
  if (loginRes.ok) {
    loginData = await loginRes.json()
  } else {
    await page.goto('/login')
    return
  }

  // If MFA is required, we can't auto-login.
  if (loginData.mfa_required) {
    await page.goto('/login')
    return
  }

  // Navigate to a blank page first to set localStorage before the app loads.
  await page.goto('/login')
  await page.waitForLoadState('domcontentloaded')

  // Inject refresh token.
  await page.evaluate((token) => {
    localStorage.setItem('akeso-refresh-token', token)
  }, loginData.refresh_token)

  // Navigate to dashboard and wait for auth guard to resolve + sidebar to render.
  await page.goto('/')
  await waitForDashboard(page)
}

/**
 * Wait for the dashboard to fully load (auth guard resolved + sidebar visible).
 */
export async function waitForDashboard(page: Page) {
  // Wait for the auth loading screen to disappear and sidebar nav to appear.
  await expect(page.locator('nav a[href="/"]')).toBeVisible({ timeout: 15000 })
}

/**
 * Navigate to a dashboard page and wait for it to load.
 */
export async function navigateTo(page: Page, path: string, waitForText: string) {
  await page.goto(path)
  await page.waitForLoadState('domcontentloaded')
  await expect(page.locator(`text=${waitForText}`).first()).toBeVisible({ timeout: 15000 })
}

/**
 * Login via the UI form (for auth flow tests).
 */
export async function loginViaUI(page: Page, username: string, password: string) {
  await page.goto('/login')
  await page.waitForLoadState('networkidle')
  await expect(page.locator('#username')).toBeVisible({ timeout: 10000 })
  await page.fill('#username', username)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')
}
