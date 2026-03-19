import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Alerts Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('page loads without errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await navigateTo(page, '/alerts', 'Alerts')

    const criticalErrors = errors.filter(
      (e) => !e.includes('ResizeObserver') && !e.includes('Non-Error')
    )
    expect(criticalErrors).toEqual([])
  })

  test('page title shows Alerts', async ({ page }) => {
    await navigateTo(page, '/alerts', 'Alerts')
    await expect(page).toHaveTitle(/Alerts.*AkesoSIEM/)
  })

  test('navigates to Alerts from sidebar', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await page.click('nav a[href="/alerts"]')
    await page.waitForURL(/\/alerts/, { timeout: 10000 })
    await expect(page.locator('text=Alerts').first()).toBeVisible({ timeout: 10000 })
  })
})
