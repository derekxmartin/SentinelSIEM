import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Hunt Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('page loads without errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await navigateTo(page, '/hunt', 'Hunt')

    const criticalErrors = errors.filter(
      (e) => !e.includes('ResizeObserver') && !e.includes('Non-Error')
    )
    expect(criticalErrors).toEqual([])
  })

  test('page title shows Hunt', async ({ page }) => {
    await navigateTo(page, '/hunt', 'Hunt')
    await expect(page).toHaveTitle(/Hunt.*AkesoSIEM/)
  })

  test('navigates to Hunt from sidebar', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await page.click('nav a[href="/hunt"]')
    await page.waitForURL(/\/hunt/, { timeout: 10000 })
    await expect(page.locator('text=Hunt').first()).toBeVisible({ timeout: 10000 })
  })
})
