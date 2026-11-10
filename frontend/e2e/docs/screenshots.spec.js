import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { test, expect } from '@playwright/test'
import { buildSamplePe, phishingEml } from '../helpers.js'

/*
 * Screenshots of the user guide (docs/guide.html), saved to docs/img/.
 *
 * Not part of the test suite: run it by hand after a change to the interface
 * (`npm run docs:screenshots`, see playwright.docs.config.js). It drives a
 * fresh install like the smoke test, with the evidence of e2e/fixtures/ and
 * the generated sample and e-mail, then captures each screen. Start the packet
 * capture worker and set E2E_PCAP_URL / E2E_PCAP_TOKEN for the Network
 * screenshots; without it they are skipped.
 */

const ADMIN = { username: 'admin', password: 'supersecret' }
const OUT = new URL('../../../docs/img/', import.meta.url)

test.describe.configure({ mode: 'serial', retries: 0 })

let page

const tabs = () => page.locator('nav[aria-label="Analysis tabs"]')
/** Save the page as docs/img/<name>.png, with the mouse out of the way (no hover state). */
async function shot(name) {
  await page.mouse.move(0, 0)
  await page.screenshot({ path: fileURLToPath(new URL(`${name}.png`, OUT)) })
}

/** Drop a file on the app as from the file manager; the "Add a file" dialog stays open. */
async function drop(name, bytes) {
  const transfer = await page.evaluateHandle(
    ([fileName, base64]) => {
      const raw = atob(base64)
      const data = new DataTransfer()
      data.items.add(new File([Uint8Array.from(raw, (c) => c.charCodeAt(0))], fileName))
      return data
    },
    [name, Buffer.from(bytes).toString('base64')],
  )
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  const dialog = page.getByRole('dialog', { name: 'Add a file' })
  await expect(dialog).toBeVisible()
  return dialog
}

async function importFile(name, bytes) {
  const dialog = await drop(name, bytes)
  await dialog.getByRole('button', { name: 'Import' }).click()
  await expect(dialog).toBeHidden()
}

const fixture = (name) => readFileSync(new URL(`../fixtures/${name}`, import.meta.url))

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage({ viewport: { width: 1600, height: 1000 } })
})

test.afterAll(async () => {
  await page.close()
})

test('sign-in and a new incident', async () => {
  await page.goto('/')
  await page.fill('#setup-username', ADMIN.username)
  await page.fill('#setup-password', ADMIN.password)
  await page.fill('#setup-confirm', ADMIN.password)
  await page.click('button[type=submit]')
  await expect(page.locator('#login-username')).toBeVisible()
  await page.fill('#login-username', ADMIN.username)
  await shot('sign-in')
  await page.fill('#login-password', ADMIN.password)
  await page.click('button[type=submit]')
  await expect(page.getByText('No active incident')).toBeVisible()

  await page.click('aside >> text=New incident')
  await page.fill('#new-ticket', 'INC-2041')
  await page.fill('#new-title', 'Invoice phishing, finance')
  await page.fill('#new-host', 'WKS-FINANCE-01')
  await page.fill('#new-username', 'm.rossi')
  await shot('new-incident')
  await page.click('button[type=submit]:has-text("Create incident")')
  await expect(page.getByText('Incident details')).toBeVisible()
})

test('evidence dropped on the app', async () => {
  const dialog = await drop('nik-eventlogs.json', fixture('nik-eventlogs.json'))
  await shot('add-file')
  await dialog.getByRole('button', { name: 'Import' }).click()
  await expect(dialog).toBeHidden()
  for (const name of ['Bookmarks', 'bash_history', 'bam-export.csv']) await importFile(name, fixture(name))
  await importFile('reported.eml', Buffer.from(phishingEml()))
  await expect(page.getByRole('list', { name: 'Messages' })).toContainText('Your account will be suspended', {
    timeout: 60_000,
  })
  await importFile('invoice_0423.pdf.exe', buildSamplePe())
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('invoice_0423.pdf.exe', { timeout: 60_000 })
})

test('the host tabs', async () => {
  await tabs().getByText('Event Logs').click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('event-logs')
  await tabs().getByText('Endpoint Artifacts').click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('endpoint')
  await tabs().getByText('Browser Forensics').click()
  await page
    .getByRole('navigation', { name: 'Browser analysis sections' })
    .getByRole('button', { name: /^Bookmarks/ })
    .click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('browser')
  await tabs().getByText('Command History').click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('commands')
})

test('the threat tabs', async () => {
  await tabs().getByText('Mail Analysis').click()
  await expect(page.getByText(/^phishing · \d+$/)).toBeVisible({ timeout: 30_000 })
  await shot('mail')
  await tabs().getByText('Malware Analysis').click()
  await page.getByRole('list', { name: 'Samples' }).getByText('invoice_0423.pdf.exe').click()
  await expect(page.getByText('PE32 executable').first()).toBeVisible({ timeout: 30_000 })
  await shot('malware')
})

test('a packet capture', async () => {
  test.skip(!process.env.E2E_PCAP_URL, 'the packet capture worker is not running')
  await tabs().getByText('Network Analysis').click()
  await page
    .getByRole('button', { name: 'Upload packet captures' })
    .locator('input[type=file]')
    .setInputFiles(fileURLToPath(new URL('../fixtures/phish.pcapng', import.meta.url)))
  await page.getByRole('list', { name: 'Captures' }).getByText('phish.pcapng').click()
  await page.getByRole('tab', { name: 'Packets' }).click({ timeout: 60_000 })
  const packets = page.getByRole('table', { name: 'Packets' })
  await packets.locator('tbody tr').nth(5).click()
  await page.getByRole('tree', { name: 'Packet details' }).getByText('Hypertext Transfer Protocol').click()
  await shot('network-packets')
  await page.getByRole('tab', { name: 'Summary' }).click()
  await expect(page.getByText('6 connections every 30 s')).toBeVisible()
  await shot('network-summary')
})

test('the overview tabs', async () => {
  await tabs().getByText('Timeline').click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('timeline')
  await tabs().getByText('IOCs').click()
  await expect(page.getByRole('button', { name: '185.220.101.47', exact: true })).toBeVisible({ timeout: 20_000 })
  await shot('iocs')
  await tabs().getByText('Summary').click()
  await expect(page.getByText('Incident details')).toBeVisible()
  await shot('summary')
})

test('search, report and settings', async () => {
  await page.keyboard.press('ControlOrMeta+k')
  const palette = page.getByRole('dialog', { name: 'Search' })
  await palette.getByRole('textbox', { name: 'Search' }).fill('185.220.101')
  await expect(palette.getByRole('option').first()).toBeVisible()
  await shot('search')
  await page.keyboard.press('Escape')

  await page.getByRole('button', { name: 'Incident report' }).click()
  const report = page.getByRole('dialog', { name: 'Incident report' })
  await report.getByRole('textbox').fill('Invoice phishing: a remote shell from 185.220.101.47 after a malicious link.')
  await report.getByRole('button', { name: 'Preview' }).click()
  const frame = page.frameLocator('iframe[title="Report preview"]')
  await expect(frame.getByRole('heading', { name: 'Incident report' })).toBeVisible({ timeout: 20_000 })
  await shot('report')
  await page.keyboard.press('Escape')

  await page.getByRole('button', { name: 'Open platform settings' }).click()
  await expect(page.getByRole('dialog', { name: 'Settings' })).toBeVisible()
  await shot('settings')
  await page.keyboard.press('Escape')
})
