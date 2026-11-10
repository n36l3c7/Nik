import { test, expect } from '@playwright/test'

/*
 * Smoke test of the whole stack, as an analyst would use it on a fresh
 * install: create the first (admin) account, sign in, open an incident, load
 * the demo data of each tab and check that the timeline and the tail -f panel
 * see the events. One browser context is shared by the steps, in order.
 */

const ADMIN = { username: 'admin', password: 'supersecret' }

// No retries: the steps share one server and one account, so a retry from the
// first step can only fail ("first run" is over) and hide the real error.
test.describe.configure({ mode: 'serial', retries: 0 })

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
  for (const tab of ['Browser Forensics', 'Command History', 'Endpoint Artifacts', 'Event Logs']) {
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

test('the IOCs tab gathers the indicators and shows where they were seen', async () => {
  await page.locator('nav[aria-label="Analysis tabs"]').getByText('IOCs').click()
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
  await page.locator('nav[aria-label="Analysis tabs"]').getByText('IOCs').click()
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
  await page.keyboard.press('Escape')
})

test('a sample is stored, analysed and shown with its indicators', async () => {
  // With the real workers this test waits for rizin, two capa rule checks
  // (~10 s each) and a second capa run: more than the 60 s default.
  if (process.env.E2E_ANALYZER_URL || process.env.E2E_CAPA_URL) test.setTimeout(300_000)
  await page.locator('nav[aria-label="Analysis tabs"]').getByText('Malware Analysis').click()
  await expect(page.getByText('No samples yet')).toBeVisible()
  // A harmless but valid PE32 (one .text section) with a few indicators inside.
  // .text starts with real x86 code at the entry point (test, branch, call a
  // helper, return) so the analyzer has functions and a CFG to show. The helper
  // loads the URL's address (mov eax, imm32), so the URL is linked to it.
  const payload = Buffer.from(
    '\0\0kernel32.dll\0VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0http://185.220.101.47/gate.php\0' +
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpd\0',
    'latin1',
  )
  const entry = Buffer.from('5589e585c07405e8030000005dc390', 'hex')
  const helper = Buffer.from('b80000000031c0c3', 'hex')
  helper.writeUInt32LE(0x401000 + entry.length + helper.length + payload.indexOf('http'), 1)
  const code = Buffer.concat([entry, helper])
  const fileAlign = 0x200
  const rawSize = Math.ceil((code.length + payload.length) / fileAlign) * fileAlign
  const headers = Buffer.alloc(0x200)
  headers.write('MZ', 0, 'ascii')
  headers.writeUInt32LE(0x80, 0x3c)
  headers.write('PE\0\0', 0x80, 'ascii')
  // IMAGE_FILE_HEADER: i386, 1 section, timestamp, optional header size 0xe0, EXECUTABLE_IMAGE | 32BIT
  headers.writeUInt16LE(0x014c, 0x84)
  headers.writeUInt16LE(1, 0x86)
  headers.writeUInt32LE(0x5f5e1000, 0x88)
  headers.writeUInt16LE(0xe0, 0x94)
  headers.writeUInt16LE(0x0102, 0x96)
  // IMAGE_OPTIONAL_HEADER32
  const opt = 0x98
  headers.writeUInt16LE(0x10b, opt) // PE32 magic
  headers.writeUInt32LE(rawSize, opt + 4) // SizeOfCode
  headers.writeUInt32LE(0x1000, opt + 16) // AddressOfEntryPoint
  headers.writeUInt32LE(0x1000, opt + 20) // BaseOfCode
  headers.writeUInt32LE(0x400000, opt + 28) // ImageBase
  headers.writeUInt32LE(0x1000, opt + 32) // SectionAlignment
  headers.writeUInt32LE(fileAlign, opt + 36) // FileAlignment
  headers.writeUInt16LE(6, opt + 40) // MajorOperatingSystemVersion
  headers.writeUInt16LE(6, opt + 48) // MajorSubsystemVersion
  headers.writeUInt32LE(0x2000, opt + 56) // SizeOfImage
  headers.writeUInt32LE(0x200, opt + 60) // SizeOfHeaders
  headers.writeUInt16LE(2, opt + 68) // Subsystem: Windows GUI
  headers.writeUInt32LE(0x100000, opt + 72) // SizeOfStackReserve
  headers.writeUInt32LE(0x1000, opt + 76)
  headers.writeUInt32LE(0x100000, opt + 80)
  headers.writeUInt32LE(0x1000, opt + 84)
  headers.writeUInt32LE(16, opt + 92) // NumberOfRvaAndSizes
  // IMAGE_SECTION_HEADER for .text
  const sec = opt + 0xe0
  headers.write('.text', sec, 'ascii')
  headers.writeUInt32LE(code.length + payload.length, sec + 8) // VirtualSize
  headers.writeUInt32LE(0x1000, sec + 12) // VirtualAddress
  headers.writeUInt32LE(rawSize, sec + 16) // SizeOfRawData
  headers.writeUInt32LE(0x200, sec + 20) // PointerToRawData
  headers.writeUInt32LE(0x60000020, sec + 36) // CODE | EXECUTE | READ
  const body = Buffer.alloc(rawSize)
  code.copy(body)
  payload.copy(body, code.length)
  await page
    .getByRole('button', { name: 'Upload malware samples' })
    .locator('input[type=file]')
    .setInputFiles({
      name: 'invoice_0423.pdf.exe',
      mimeType: 'application/octet-stream',
      buffer: Buffer.concat([headers, body]),
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
  const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200)]).toString('base64')
  const eml = [
    'Received: from mail.evil.example (mail.evil.example [185.220.101.47]) by mx.contoso.example; Tue, 10 Nov 2026 09:00:02 +0100',
    'From: "PayPal Service" <service@paypai.example>',
    'Reply-To: refunds@freemail.example',
    'To: m.rossi@contoso.example',
    'Subject: Your account will be suspended',
    'Date: Tue, 10 Nov 2026 08:59:50 +0100',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b1"',
    '',
    '--b1',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Verify your account immediately.</p><p style="font-size:0">filler</p>' +
      '<a href="https://login-paypa1.top/x">https://www.paypal.com/signin</a><script>alert(1)</script>',
    '--b1',
    'Content-Type: application/octet-stream; name="invoice.pdf.exe"',
    'Content-Disposition: attachment; filename="invoice.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    '',
    exe,
    '--b1--',
    '',
  ].join('\r\n')
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
  await page.locator('nav[aria-label="Analysis tabs"]').getByText('Mail Analysis').click()
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
    await remote.getByRole('button', { name: 'Close' }).click()
  } else {
    await expect(browse).toBeDisabled()
  }
})

test('the API is reachable through the same origin', async ({ request }) => {
  const health = await request.get('/api/health')
  expect(health.ok()).toBeTruthy()
  const ready = await request.get('/api/ready')
  expect(ready.ok()).toBeTruthy()
})
