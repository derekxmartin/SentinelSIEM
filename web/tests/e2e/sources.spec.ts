import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Sources Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('page loads without errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await navigateTo(page, '/sources', 'Sources')

    const criticalErrors = errors.filter(
      (e) => !e.includes('ResizeObserver') && !e.includes('Non-Error')
    )
    expect(criticalErrors).toEqual([])
  })

  test('page title shows Sources', async ({ page }) => {
    await navigateTo(page, '/sources', 'Sources')
    await expect(page).toHaveTitle(/Sources.*AkesoSIEM/)
  })

  test('onboarding wizard button is visible', async ({ page }) => {
    await navigateTo(page, '/sources', 'Sources')
    const addButton = page.locator('button:has-text("Add Source"), button:has-text("Onboard")')
    await expect(addButton.first()).toBeVisible({ timeout: 15000 })
  })

  test('clicking Add Source opens wizard', async ({ page }) => {
    await navigateTo(page, '/sources', 'Sources')
    const addButton = page.locator('button:has-text("Add Source"), button:has-text("Onboard")')
    await addButton.first().click()

    // Wizard should show step content.
    await expect(
      page.locator('text=Source Type').or(page.locator('text=Step')).or(page.locator('text=Select')).first()
    ).toBeVisible({ timeout: 10000 })
  })

  test('navigates to Sources from sidebar', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await page.click('nav a[href="/sources"]')
    await page.waitForURL(/\/sources/, { timeout: 10000 })
    await expect(page.locator('text=Sources').first()).toBeVisible({ timeout: 10000 })
  })
})
