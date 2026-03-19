import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Overview Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('renders KPI cards', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    const cards = page.locator('[class*="rounded-lg"]').filter({ hasText: /Total|Active|Critical|Sources/ })
    await expect(cards.first()).toBeVisible({ timeout: 15000 })
  })

  test('renders charts without JS errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await navigateTo(page, '/', 'Overview')
    await page.waitForTimeout(3000) // Let charts fully render.

    const criticalErrors = errors.filter(
      (e) => !e.includes('ResizeObserver') && !e.includes('Non-Error')
    )
    expect(criticalErrors).toEqual([])
  })

  test('page title includes AkesoSIEM', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await expect(page).toHaveTitle(/AkesoSIEM/)
  })

  test('sidebar navigation links are visible', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await expect(page.locator('nav a[href="/"]')).toBeVisible()
    await expect(page.locator('nav a[href="/alerts"]')).toBeVisible()
    await expect(page.locator('nav a[href="/rules"]')).toBeVisible()
    await expect(page.locator('nav a[href="/sources"]')).toBeVisible()
  })
})
