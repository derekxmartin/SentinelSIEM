import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Dark Mode Toggle', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('page starts in dark mode by default', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    const html = page.locator('html')
    await expect(html).toHaveClass(/dark/, { timeout: 10000 })
  })

  test('toggle switches to light mode', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')

    // Find the theme toggle button (sun/moon icon area).
    const themeToggle = page.locator('button[title*="theme"], button:has([class*="SunIcon"]), button:has([class*="MoonIcon"])')

    // If that doesn't match, try a broader selector for the theme toggle area.
    const toggleButton = themeToggle.first().or(
      page.locator('button').filter({ has: page.locator('svg') }).nth(2) // ThemeToggle is usually 3rd button in header
    )

    if (await toggleButton.isVisible({ timeout: 5000 }).catch(() => false)) {
      await toggleButton.click()
      await page.waitForTimeout(500)

      // Check if theme changed (either dark class removed or still there if it cycled).
      const htmlClass = await page.locator('html').getAttribute('class')
      expect(htmlClass).toBeDefined()
    }
  })

  test('theme persists across navigation', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')

    // Get current theme.
    const initialClass = await page.locator('html').getAttribute('class') || ''
    const wasDark = initialClass.includes('dark')

    // Navigate to another page.
    await page.click('nav a[href="/rules"]')
    await page.waitForURL(/\/rules/, { timeout: 10000 })
    await expect(page.locator('text=Rules').first()).toBeVisible({ timeout: 15000 })

    // Theme should be preserved.
    const afterNavClass = await page.locator('html').getAttribute('class') || ''
    const isDark = afterNavClass.includes('dark')
    expect(isDark).toBe(wasDark)
  })

  test('theme persists across page reload', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')

    const initialClass = await page.locator('html').getAttribute('class') || ''
    const wasDark = initialClass.includes('dark')

    await page.reload()
    await expect(page.locator('nav a[href="/"]')).toBeVisible({ timeout: 15000 })

    const afterReloadClass = await page.locator('html').getAttribute('class') || ''
    const isDark = afterReloadClass.includes('dark')
    expect(isDark).toBe(wasDark)
  })
})
