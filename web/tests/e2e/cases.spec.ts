import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Cases Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('page loads without errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await navigateTo(page, '/cases', 'Cases')

    const criticalErrors = errors.filter(
      (e) => !e.includes('ResizeObserver') && !e.includes('Non-Error')
    )
    expect(criticalErrors).toEqual([])
  })

  test('page title shows Cases', async ({ page }) => {
    await navigateTo(page, '/cases', 'Cases')
    await expect(page).toHaveTitle(/Cases.*AkesoSIEM/)
  })

  test('navigates to Cases from sidebar', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await page.click('nav a[href="/cases"]')
    await page.waitForURL(/\/cases/, { timeout: 10000 })
    await expect(page.locator('text=Cases').first()).toBeVisible({ timeout: 10000 })
  })
})
