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
 * screenshots, the isolated browser (E2E_BROWSER_URL / E2E_BROWSER_TOKEN) and
 * DOCS_SCAN_URL for the URL Analysis one; without them they are skipped.
 */

const ADMIN = { username: 'admin', password: 'supersecret' }
const OUT = new URL('../../../docs/img/', import.meta.url)

test.describe.configure({ mode: 'serial', retries: 0 })

let page

const tabs = () => page.locator('nav[aria-label="Analysis tabs"]')
const evidence = () => page.getByRole('navigation', { name: 'Evidence' })

/** A kind of evidence, whole: the Evidence tab, then the name of the kind in its list. */
async function kind(name) {
  await tabs().getByRole('button', { name: 'Evidence', exact: true }).click()
  await evidence().getByRole('button', { name, exact: true }).click()
}
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
  await expect(page.getByRole('heading', { name: 'No incidents yet' })).toBeVisible()

  await page.getByRole('region', { name: 'Incidents' }).getByRole('button', { name: 'New incident' }).first().click()
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
  await kind('Event Logs')
  // The incident was made with no system: what was collected on the machine asks for it first.
  const system = page.getByRole('dialog', { name: 'Which system is this incident about?' })
  await expect(system).toBeVisible()
  await system.getByRole('button', { name: 'Use Windows' }).click()
  await expect(system).toBeHidden()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('event-logs')
  await kind('Endpoint Artifacts')
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('endpoint')
  await kind('Browser Forensics')
  await page
    .getByRole('navigation', { name: 'Browser analysis sections' })
    .getByRole('button', { name: /^Bookmarks/ })
    .click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('browser')
  await kind('Command History')
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('commands')
})

test('the threat tabs', async () => {
  await kind('Mail Analysis')
  await expect(page.getByText(/^phishing · \d+$/)).toBeVisible({ timeout: 30_000 })
  await shot('mail')
  await kind('Malware Analysis')
  await page.getByRole('list', { name: 'Samples' }).getByText('invoice_0423.pdf.exe').click()
  await expect(page.getByText('PE32 executable').first()).toBeVisible({ timeout: 30_000 })
  await shot('malware')
  // The right-click menu, the same everywhere: here on a sample of the list.
  await page.getByRole('list', { name: 'Samples' }).getByText('invoice_0423.pdf.exe').click({ button: 'right' })
  await expect(page.getByRole('menu')).toBeVisible()
  await page.screenshot({ path: fileURLToPath(new URL('context-menu.png', OUT)) })
  // Flagged: it goes into the report previewed further down.
  await page.getByRole('menu').getByRole('menuitem', { name: 'Flag the sample' }).click()
})

test('artifacts on their own', async () => {
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel.getByRole('button', { name: 'New analysis' }).click()
  await expect(page.getByRole('dialog', { name: 'New analysis' })).toBeVisible()
  await shot('new-analysis')
  await page.keyboard.press('Escape')
  // The reported e-mail, opened as an artifact: its incident, its tags, the same analysis.
  await panel.getByRole('navigation', { name: 'Artifacts' }).getByText('Your account will be suspended').click()
  const artifact = page.getByRole('region', { name: 'Artifact' })
  await expect(artifact.getByRole('heading', { name: 'Your account will be suspended' })).toBeVisible()
  await artifact.getByRole('button', { name: 'Add tags' }).click()
  await artifact.getByLabel('Tags').fill('phishing-kit campaign:q4')
  await artifact.getByRole('button', { name: 'Save' }).click()
  await expect(artifact).toContainText('#phishing-kit')
  await expect(page.getByText(/^phishing · \d+$/).first()).toBeVisible({ timeout: 30_000 })
  await shot('artifact')
  await artifact.getByRole('button', { name: '[INC-2041] Invoice phishing, finance', exact: true }).click()
  // The list of incidents, and back: the side panel of the artifacts is left without being closed for good.
  await page.getByRole('button', { name: 'Incidents', exact: true }).click()
  await page.getByRole('button', { name: 'Hide the incidents' }).click()
})

test('an address scanned by the isolated browser', async () => {
  // DOCS_SCAN_URL: an address the isolated browser worker can reach that serves
  // e2e/fixtures/signin.html (the worker refuses private addresses).
  test.skip(!process.env.E2E_BROWSER_URL || !process.env.DOCS_SCAN_URL, 'no isolated browser or no page to scan')
  await kind('URL Analysis')
  await page.getByLabel('Address to scan').fill(process.env.DOCS_SCAN_URL)
  await page.getByRole('button', { name: 'Scan', exact: true }).click()
  await expect(page.getByText('WHY THIS VERDICT')).toBeVisible({ timeout: 120_000 })
  await expect(page.getByRole('img', { name: /^Screenshot of/ })).toBeVisible()
  await page.waitForLoadState('networkidle')
  await shot('url')
})

test('a packet capture', async () => {
  test.skip(!process.env.E2E_PCAP_URL, 'the packet capture worker is not running')
  await kind('Network Analysis')
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
  await tabs().getByRole('button', { name: 'Timeline', exact: true }).click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  await shot('timeline')
  await tabs().getByRole('button', { name: 'Indicators', exact: true }).click()
  await expect(page.getByRole('button', { name: '185.220.101.47', exact: true })).toBeVisible({ timeout: 20_000 })
  await shot('iocs')
  await tabs().getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.getByText('Incident details')).toBeVisible()
  // The pointer off the bar: no tab looks chosen but the one that is.
  await page.mouse.move(900, 700)
  await page.waitForTimeout(400)
  await shot('summary')
})

test('the evidence tab and the playground', async () => {
  // A file of the list, opened alone in the page of its kind.
  await tabs().getByRole('button', { name: 'Evidence', exact: true }).click()
  await evidence().getByRole('list', { name: 'Files of Mail Analysis' }).getByRole('button').first().click()
  await expect(page.getByText('Why this verdict').first()).toBeVisible({ timeout: 20_000 })
  await shot('evidence')

  await page.getByRole('button', { name: 'Playground', exact: true }).click()
  const room = page.getByRole('region', { name: 'Playground' })
  const line = room.locator('#playground-line')
  await line.fill('!nik-get-indicator 185.220.101.47')
  await line.press('Enter')
  const result = room
    .getByRole('list', { name: 'Playground' })
    .getByRole('listitem')
    .filter({ hasText: /nik-get-indicator/ })
    .nth(1)
  await expect(result).toBeVisible({ timeout: 30_000 })
  await line.fill('try the mail instance on the test tenant first')
  await line.press('Enter')
  await result.getByRole('button').first().click()
  await expect(room.getByRole('heading', { name: 'Result' })).toBeVisible()
  await shot('playground')
  await room.getByRole('button', { name: 'Close the playground' }).click()
})

test('pasted text', async () => {
  await page.evaluate(() => {
    const data = new DataTransfer()
    data.setData('text/plain', 'hxxps://login-paypa1[.]top/signin?id=8841')
    document.body.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true }))
  })
  await expect(page.getByRole('region', { name: 'Pasted text' })).toBeVisible()
  await shot('paste')
  await page.getByRole('region', { name: 'Pasted text' }).getByRole('button', { name: 'Dismiss' }).click()
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
  await expect(page.getByRole('region', { name: 'Settings' })).toBeVisible()
  await shot('settings')
  await page.keyboard.press('Escape')
})
