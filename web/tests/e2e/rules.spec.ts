import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateTo } from './helpers'

test.describe('Rules Page', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('rules list loads grouped by tactic', async ({ page }) => {
    await navigateTo(page, '/rules', 'Rules')

    // Should show tactic group headers (e.g., Initial Access, Execution, etc.)
    await expect(
      page.locator('text=Initial Access').or(page.locator('text=Execution')).first()
    ).toBeVisible({ timeout: 15000 })
  })

  test('page title shows Rules', async ({ page }) => {
    await navigateTo(page, '/rules', 'Rules')
    await expect(page).toHaveTitle(/Rules.*AkesoSIEM/)
  })

  test('toggle between Detection Rules and ATT&CK Coverage tabs', async ({ page }) => {
    await navigateTo(page, '/rules', 'Rules')

    // Click ATT&CK Coverage tab.
    const attackTab = page.locator('button:has-text("ATT&CK"), button:has-text("Coverage")')
    await expect(attackTab.first()).toBeVisible({ timeout: 15000 })
    await attackTab.first().click()

    // Heatmap should render.
    await expect(page.locator('text=ATT&CK').or(page.locator('text=Coverage')).first()).toBeVisible({ timeout: 10000 })
  })

  test('ATT&CK heatmap renders without JS errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', (err) => errors.push(err.message))

    await navigateTo(page, '/rules', 'Rules')

    // Switch to heatmap tab.
    const attackTab = page.locator('button:has-text("ATT&CK"), button:has-text("Coverage")')
    await expect(attackTab.first()).toBeVisible({ timeout: 15000 })
    await attackTab.first().click()
    await page.waitForTimeout(2000)

    const criticalErrors = errors.filter(
      (e) => !e.includes('ResizeObserver') && !e.includes('Non-Error')
    )
    expect(criticalErrors).toEqual([])
  })

  test('rule toggle switch is visible', async ({ page }) => {
    await navigateTo(page, '/rules', 'Rules')

    // Toggle switches should be present for rules.
    const toggles = page.locator('button[class*="rounded-full"]').filter({ has: page.locator('span[class*="rounded-full"]') })
    await expect(toggles.first()).toBeVisible({ timeout: 15000 })
  })

  test('KPI cards show rule stats', async ({ page }) => {
    await navigateTo(page, '/rules', 'Rules')

    // Should show Total Rules, Enabled, Total Hits cards.
    await expect(page.locator('text=Total Rules')).toBeVisible({ timeout: 15000 })
  })
})
