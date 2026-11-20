import test from 'node:test'
import assert from 'node:assert/strict'
import {
  ACTIVE_MS,
  accountsToEnrol,
  browserName,
  cleanCode,
  clockAfterUse,
  countdown,
  factorState,
  groupedSecret,
  isBackground,
  isCode,
  isNetwork,
  keepAliveMs,
  minutesWords,
  mustEnrol,
  needsKeepAlive,
  parseNetworks,
  policyChanges,
  policyForm,
  recoveryCodesFile,
  recoveryCodesLeftText,
  sessionClock,
  sessionPhase,
} from './signin.js'

const T0 = Date.parse('2027-01-15T08:00:00Z')

test('a request is the person’s for a moment after they did something, the page’s own afterwards', () => {
  assert.equal(isBackground(T0, T0), false)
  assert.equal(isBackground(T0, T0 + ACTIVE_MS), false)
  assert.equal(isBackground(T0, T0 + ACTIVE_MS + 1), true)
})

test('the server is told the person is there a few times per idle time, never more than once in ten seconds', () => {
  assert.equal(keepAliveMs(0), 60_000)
  assert.equal(keepAliveMs(30 * 60), 60_000)
  assert.equal(keepAliveMs(120), 30_000)
  assert.equal(keepAliveMs(20), 10_000)
  assert.equal(needsKeepAlive(T0, T0 + 59_999, 60_000), false)
  assert.equal(needsKeepAlive(T0, T0 + 60_000, 60_000), true)
})

test('the clock of a session: fine, then the server is asked, then the warning, then over', () => {
  const clock = sessionClock({ idleSeconds: 1800, idleLeft: 1800, lifetimeLeft: 43200, warnSeconds: 60 }, T0)
  assert.deepEqual(sessionPhase(clock, T0), { phase: 'fine', reason: 'idle', left: 1800 })
  assert.equal(sessionPhase(clock, T0 + 1694_000).phase, 'fine')
  assert.equal(sessionPhase(clock, T0 + 1696_000).phase, 'check')
  assert.deepEqual(sessionPhase(clock, T0 + 1750_000), { phase: 'warn', reason: 'idle', left: 50 })
  assert.deepEqual(sessionPhase(clock, T0 + 1800_000), { phase: 'over', reason: 'idle', left: 0 })
  // After a request of the person the idle time counts again, as a guess: the warning waits for the server's word.
  const used = clockAfterUse(clock, T0 + 600_000)
  assert.equal(used.idleEndsAt, T0 + 600_000 + 1800_000)
  assert.equal(sessionPhase(used, T0 + 600_000 + 1750_000).phase, 'check')
  assert.equal(
    sessionPhase(sessionClock({ idleSeconds: 1800, idleLeft: 50, lifetimeLeft: 9000, warnSeconds: 60 }, T0), T0).phase,
    'warn',
  )
})

test('the lifetime ends a session that is used, with a warning of its own', () => {
  const clock = sessionClock({ idleSeconds: 1800, idleLeft: 1800, lifetimeLeft: 100, warnSeconds: 60 }, T0)
  assert.deepEqual(sessionPhase(clock, T0), { phase: 'check', reason: 'lifetime', left: 100 })
  assert.deepEqual(sessionPhase(clock, T0 + 50_000), { phase: 'warn', reason: 'lifetime', left: 50 })
  assert.equal(sessionPhase(clockAfterUse(clock, T0 + 90_000), T0 + 100_000).phase, 'over')
  // No idle limit: only the lifetime counts, and a request changes nothing.
  const endless = sessionClock({ idleSeconds: 0, idleLeft: null, lifetimeLeft: 7200, warnSeconds: 0 }, T0)
  assert.equal(endless.idleEndsAt, null)
  assert.equal(clockAfterUse(endless, T0 + 5), endless)
  assert.deepEqual(sessionPhase(endless, T0), { phase: 'fine', reason: 'lifetime', left: 7200 })
  assert.deepEqual(sessionPhase(null, T0), { phase: 'fine', reason: null, left: null })
})

test('times are said as a countdown and in words', () => {
  assert.equal(countdown(42), '0:42')
  assert.equal(countdown(125), '2:05')
  assert.equal(countdown(-3), '0:00')
  assert.equal(minutesWords(0), 'never')
  assert.equal(minutesWords(1), '1 minute')
  assert.equal(minutesWords(30), '30 minutes')
  assert.equal(minutesWords(60), '1 hour')
  assert.equal(minutesWords(90), '1 hour 30 minutes')
  assert.equal(minutesWords(480), '8 hours')
})

test('a code is its six digits, however it was typed or pasted', () => {
  assert.equal(cleanCode('123 456'), '123456')
  assert.equal(cleanCode(' 12-34-56 \n'), '123456')
  assert.equal(cleanCode('1234567890'), '123456')
  assert.equal(cleanCode('abc'), '')
  assert.equal(cleanCode(null), '')
  assert.equal(isCode('123456'), true)
  assert.equal(isCode('12345'), false)
  assert.equal(isCode('12345a'), false)
  assert.equal(groupedSecret('GEZDGNBVGY3TQOJQ'), 'GEZD GNBV GY3T QOJQ')
  assert.equal(groupedSecret(''), '')
})

test('the recovery codes are a file a person can keep, and what is left is said plainly', () => {
  const file = recoveryCodesFile(['aaaa-bbbb-cccc-dddd', 'eeee-ffff-gggg-hhhh'], 'anna', new Date(T0))
  assert.ok(file.startsWith('Nik recovery codes for anna\nMade on 2027-01-15\n'))
  assert.ok(file.endsWith('\naaaa-bbbb-cccc-dddd\neeee-ffff-gggg-hhhh\n'))
  assert.match(recoveryCodesLeftText(9), /You have 9 left\.$/)
  assert.match(recoveryCodesLeftText(1), /1 left: make new ones/)
  assert.match(recoveryCodesLeftText(0), /last recovery code\. Make new ones now/)
})

test('an account has a second factor, lacks one its roles ask for, or has none', () => {
  assert.equal(factorState({ secondFactor: true, secondFactorRequired: true }), 'on')
  assert.equal(factorState({ secondFactor: false, secondFactorRequired: true }), 'missing')
  assert.equal(factorState({ secondFactor: false, secondFactorRequired: false }), 'off')
  assert.equal(factorState(null), 'off')
  assert.equal(mustEnrol({ secondFactorRequired: true }), true)
  assert.equal(mustEnrol({ secondFactorRequired: true, secondFactor: true }), false)
  const users = [
    { username: 'a', roles: ['admin'], secondFactor: false },
    { username: 'b', roles: ['admin', 'audit'], secondFactor: true },
    { username: 'c', roles: ['analyst'], secondFactor: false },
    { username: 'd', roles: ['admin'], secondFactor: false, disabled: true },
  ]
  assert.deepEqual(
    accountsToEnrol(users, ['admin']).map((user) => user.username),
    ['a'],
  )
  assert.deepEqual(accountsToEnrol(users, []), [])
})

test('a browser is named as a person would', () => {
  const names = {
    'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0': 'Firefox 140 on Linux',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36':
      'Chrome 141 on Windows',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0':
      'Edge 141 on Windows',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.1 Safari/605.1.15':
      'Safari 19 on macOS',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1':
      'Safari 19 on iOS',
    'Mozilla/5.0 (Linux; Android 16; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36':
      'Chrome 141 on Android',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36':
      'Chrome 141 on Linux',
    'curl/8.9.1': 'curl',
    'python-requests/2.33.0': 'a Python script',
    'Mozilla/5.0 (X11; Linux x86_64) SomethingNew/1.0': 'A browser on Linux',
    '': 'An unknown browser',
    'whatever this is': 'An unknown browser',
  }
  for (const [agent, name] of Object.entries(names)) assert.equal(browserName(agent), name, agent)
  assert.equal(browserName(null), 'An unknown browser')
})

test('a network is an address or a prefix, IPv4 or IPv6', () => {
  for (const good of [
    '10.1.0.0/16',
    '192.0.2.7',
    '0.0.0.0/0',
    '2001:db8::/32',
    '::1',
    'fe80::1/64',
    '::ffff:10.0.0.1',
    '2001:db8:0:0:0:0:0:1/128',
  ]) {
    assert.equal(isNetwork(good), true, good)
  }
  for (const bad of [
    '',
    '10.1.0.0/33',
    '10.1.0/16',
    '256.1.1.1',
    'office',
    '2001:db8::/129',
    '1::2::3',
    '10.0.0.0/8/8',
    ':::',
    '12345::',
  ]) {
    assert.equal(isNetwork(bad), false, bad)
  }
  assert.deepEqual(parseNetworks('10.0.0.0/8\n\n 2001:db8::/32 , office,10.0.0.0/8'), {
    networks: ['10.0.0.0/8', '2001:db8::/32', 'office'],
    wrong: ['office'],
  })
})

test('the policy form sends only what changed, and says what cannot be sent', () => {
  const policy = {
    requiredRoles: [],
    idleMinutes: 480,
    idleMinutesAdmin: 480,
    lifetimeHours: 12,
    attemptsBeforeWait: 5,
    firstWaitSeconds: 30,
    maxWaitMinutes: 15,
    notifyAfter: 10,
    adminNetworks: ['203.0.113.7/32'],
  }
  const limits = { idleMinutes: { min: 0, max: 10080 }, lifetimeHours: { min: 1, max: 720 } }
  const form = policyForm(policy)
  assert.equal(form.idleMinutes, '480')
  assert.equal(form.adminNetworks, '203.0.113.7/32')
  assert.deepEqual(policyChanges(form, policy, limits), { body: {}, problems: {} })
  // A single address typed without its /32 is what is stored.
  assert.deepEqual(policyChanges({ ...form, adminNetworks: '203.0.113.7' }, policy, limits).body, {})
  const changed = policyChanges(
    { ...form, requiredRoles: ['admin'], idleMinutesAdmin: '30', adminNetworks: '203.0.113.7\n10.0.0.0/8' },
    policy,
    limits,
  )
  assert.deepEqual(changed, {
    body: { requiredRoles: ['admin'], idleMinutesAdmin: 30, adminNetworks: ['203.0.113.7', '10.0.0.0/8'] },
    problems: {},
  })
  const wrong = policyChanges(
    {
      ...form,
      idleMinutes: '-1',
      lifetimeHours: '0',
      firstWaitSeconds: '1000',
      maxWaitMinutes: '1',
      adminNetworks: 'here',
    },
    policy,
    limits,
  )
  assert.deepEqual(Object.keys(wrong.problems).sort(), [
    'adminNetworks',
    'firstWaitSeconds',
    'idleMinutes',
    'lifetimeHours',
  ])
  assert.match(wrong.problems.lifetimeHours, /from 1 to 720/)
  // Emptying the list is a change like another.
  assert.deepEqual(policyChanges({ ...form, adminNetworks: '' }, policy, limits).body, { adminNetworks: [] })
})
