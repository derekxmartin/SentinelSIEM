import { test } from '@playwright/test'
import { loginAsAdmin, navigateTo } from '../e2e/helpers'
import path from 'path'
import { fileURLToPath } from 'url'

/**
 * Screenshot capture suite for documentation.
 *
 * Usage:
 *   npx playwright test --project=screenshots
 *
 * Screenshots are saved to web/docs/screenshots/ as PNG files.
 * Run with the dev server + backend already running.
 */

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const SCREENSHOT_DIR = path.join(__dirname, '..', '..', 'docs', 'screenshots')

test.describe('Documentation Screenshots', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('login page', async ({ browser }) => {
    // Use a fresh context (not logged in) for the login page.
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } })
    const page = await ctx.newPage()
    await page.goto('/login')
    await page.waitForLoadState('networkidle')
    await page.waitForTimeout(1000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '01-login.png'),
      fullPage: false,
    })
    await ctx.close()
  })

  test('overview dashboard', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await page.waitForTimeout(3000) // Let charts render
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '02-overview.png'),
      fullPage: false,
    })
  })

  test('alerts page', async ({ page }) => {
    await navigateTo(page, '/alerts', 'Alerts')
    await page.waitForTimeout(2000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '03-alerts.png'),
      fullPage: false,
    })
  })

  test('rules page', async ({ page }) => {
    await navigateTo(page, '/rules', 'Rules')
    await page.waitForTimeout(2000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '04-rules.png'),
      fullPage: false,
    })
  })

  test('sources page', async ({ page }) => {
    await navigateTo(page, '/sources', 'Sources')
    await page.waitForTimeout(2000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '05-sources.png'),
      fullPage: false,
    })
  })

  test('hunt page', async ({ page }) => {
    await navigateTo(page, '/hunt', 'Hunt')
    await page.waitForTimeout(2000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '06-hunt.png'),
      fullPage: false,
    })
  })

  test('cases page', async ({ page }) => {
    await navigateTo(page, '/cases', 'Cases')
    await page.waitForTimeout(2000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '07-cases.png'),
      fullPage: false,
    })
  })

  test('settings page', async ({ page }) => {
    await navigateTo(page, '/settings', 'Settings')
    await page.waitForTimeout(2000)
    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '08-settings.png'),
      fullPage: false,
    })
  })

  test('overview dark theme', async ({ page }) => {
    await navigateTo(page, '/', 'Overview')
    await page.waitForTimeout(2000)

    // Toggle to dark mode via the theme button in the header.
    const themeBtn = page.locator('button[aria-label="Toggle theme"], button:has(svg.h-5.w-5)').first()
    if (await themeBtn.isVisible()) {
      await themeBtn.click()
      await page.waitForTimeout(1500)
    }

    await page.screenshot({
      path: path.join(SCREENSHOT_DIR, '09-overview-dark.png'),
      fullPage: false,
    })
  })
})
