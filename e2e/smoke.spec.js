import { test, expect } from '@playwright/test'

/*
 * Smoke test of the whole stack, as an analyst would use it on a fresh
 * install: create the first (admin) account, sign in, open an incident, load
 * the demo data of each tab and check that the timeline and the tail -f panel
 * see the events. One browser context is shared by the steps, in order.
 */

const ADMIN = { username: 'admin', password: 'supersecret' }

test.describe.configure({ mode: 'serial' })

let page

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage()
  page.on('pageerror', (error) => {
    throw new Error(`Uncaught error in the page: ${error.message}`)
  })
})

test.afterAll(async () => {
  await page.close()
})

test('first run creates the admin account', async () => {
  await page.goto('/')
  await expect(page.getByText('first run')).toBeVisible()
  await page.fill('#setup-username', ADMIN.username)
  await page.fill('#setup-password', ADMIN.password)
  await page.fill('#setup-confirm', ADMIN.password)
  await page.click('button[type=submit]')
  await expect(page.locator('#login-username')).toBeVisible()
})

test('the admin signs in and sees the empty dashboard', async () => {
  await page.fill('#login-username', ADMIN.username)
  await page.fill('#login-password', ADMIN.password)
  await page.click('button[type=submit]')
  await expect(page.getByText('No active incident')).toBeVisible()
})

test('a new incident opens on its summary', async () => {
  await page.click('aside >> text=New incident')
  await page.fill('#new-host', 'WKS-FINANCE-01')
  await page.fill('#new-username', 'm.rossi')
  await page.click('button[type=submit]:has-text("Create incident")')
  await expect(page.getByText('Incident details')).toBeVisible()
  await expect(page.locator('aside nav[aria-label="Incidents"]')).toContainText('WKS-FINANCE-01')
})

test('demo data fills the analysis tabs', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  for (const tab of ['Browser Forensics', 'Command History', 'Endpoint Artifacts']) {
    await tabs.getByText(tab).click()
    const loaders = page.locator('button:has-text("Load demo data")')
    await expect(loaders.first()).toBeVisible({ timeout: 20_000 })
    const count = await loaders.count()
    for (let i = 0; i < count; i++) {
      await loaders.nth(i).click()
    }
    // The data-sources card records the import and the tables fill up.
    await expect(page.getByText('Demo data').first()).toBeVisible()
    await expect(page.locator('tbody tr').first()).toBeVisible()
  }
})

test('the timeline and the tail -f panel merge the events', async () => {
  await page.locator('nav[aria-label="Analysis tabs"]').getByText('Timeline').click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  const counter = page.getByText(/of \d+ results/)
  await expect(counter).toBeVisible()
  expect(await counter.textContent()).not.toMatch(/of 0 results/)

  // The tail panel is remembered per tab; make sure it is open here.
  const toggle = page.locator('button[title*="tail -f"]')
  if ((await toggle.getAttribute('title')) !== 'Hide the tail -f panel') await toggle.click()
  const tail = page.getByRole('complementary', { name: 'Latest incident events' })
  await expect(tail).toBeVisible()
  await expect(tail.locator('li')).not.toHaveCount(1) // more than the cursor line
})

test('the API is reachable through the same origin', async ({ request }) => {
  const health = await request.get('/api/health')
  expect(health.ok()).toBeTruthy()
  const ready = await request.get('/api/ready')
  expect(ready.ok()).toBeTruthy()
})
