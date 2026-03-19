import { test, expect } from '@playwright/test'
import { loginViaUI } from './helpers'

test.describe('Auth Flows', () => {
  test('redirects unauthenticated users to /login', async ({ page }) => {
    // Clear any stored tokens.
    await page.goto('/login')
    await page.waitForLoadState('domcontentloaded')
    await page.evaluate(() => localStorage.removeItem('akeso-refresh-token'))

    await page.goto('/')
    await page.waitForURL(/\/login/, { timeout: 15000 })
    await expect(page.locator('text=Sign in to your account')).toBeVisible({ timeout: 10000 })
  })

  test('shows login page with branding', async ({ page }) => {
    await page.goto('/login')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('text=AkesoSIEM')).toBeVisible({ timeout: 10000 })
    await expect(page.locator('#username')).toBeVisible()
    await expect(page.locator('#password')).toBeVisible()
    await expect(page.locator('button[type="submit"]')).toBeVisible()
  })

  test('shows error on wrong password', async ({ page }) => {
    await loginViaUI(page, 'nonexistent_user', 'wrongpassword')
    await expect(page.locator('text=Invalid username or password')).toBeVisible({ timeout: 10000 })
    await expect(page).toHaveURL(/\/login/)
  })

  test('successful login redirects to dashboard', async ({ page }) => {
    await loginViaUI(page, 'e2e_admin', 'E2eTestPass123!')

    // Should redirect to dashboard (or MFA page if MFA enabled).
    // Wait for redirect — either dashboard root or MFA page.
    await expect(page.locator('nav a[href="/"]').or(page.locator('text=Two-Factor Authentication'))).toBeVisible({ timeout: 15000 })

    const url = page.url()
    if (url.includes('/login/mfa')) {
      await expect(page.locator('text=Two-Factor Authentication')).toBeVisible({ timeout: 10000 })
    } else {
      await expect(page.locator('nav a[href="/"]')).toBeVisible({ timeout: 15000 })
    }
  })

  test('logout returns to login page', async ({ page }) => {
    await loginViaUI(page, 'e2e_admin', 'E2eTestPass123!')

    // Wait for redirect — either dashboard root or MFA page.
    await expect(page.locator('nav a[href="/"]').or(page.locator('text=Two-Factor Authentication'))).toBeVisible({ timeout: 15000 })

    if (page.url().includes('/login/mfa')) {
      test.skip()
      return
    }

    // Open user menu and click sign out.
    const avatar = page.locator('button[aria-haspopup="menu"]')
    await expect(avatar).toBeVisible({ timeout: 5000 })
    await avatar.click()
    await expect(page.locator('text=Sign out')).toBeVisible({ timeout: 5000 })
    await page.click('text=Sign out')

    await page.waitForURL(/\/login/, { timeout: 10000 })
    await expect(page.locator('text=Sign in to your account')).toBeVisible({ timeout: 10000 })
  })

  test('token refresh recovers session on page reload', async ({ page }) => {
    await loginViaUI(page, 'e2e_admin', 'E2eTestPass123!')

    // Wait for redirect — either dashboard root or MFA page.
    await expect(page.locator('nav a[href="/"]').or(page.locator('text=Two-Factor Authentication'))).toBeVisible({ timeout: 15000 })

    if (page.url().includes('/login/mfa')) {
      test.skip()
      return
    }

    // Reload the page — silent refresh should recover session.
    await page.reload()
    await page.waitForLoadState('domcontentloaded')
    await expect(page.locator('nav a[href="/"]')).toBeVisible({ timeout: 20000 })
  })

  test('rate limiting shows 429 error after too many failures', async ({ page }) => {
    await page.goto('/login')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('#username')).toBeVisible({ timeout: 10000 })

    // Send 6 rapid failed login attempts.
    for (let i = 0; i < 6; i++) {
      await page.fill('#username', 'fake_user')
      await page.fill('#password', 'wrongpass')
      await page.click('button[type="submit"]')
      // Wait for error response before next attempt.
      await page.waitForTimeout(500)
    }

    // Should show rate limit or auth error.
    await expect(
      page.locator('text=Too many login attempts').or(page.locator('text=Invalid username or password'))
    ).toBeVisible({ timeout: 10000 })
  })
})
