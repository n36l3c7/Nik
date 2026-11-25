import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  LEVEL_FILTER_OPTIONS,
  detectionTone,
  hostsText,
  levelColor,
  levelCounts,
  levelLabel,
  levelName,
  levelOf,
  levelsText,
  reportDetections,
  ruleChipValue,
  rulesAtLeast,
  summedByLevel,
  tagChips,
  tagText,
  tagUrl,
  totalOf,
} from './detections.js'

test('a level is known by its number or its name, and nothing else is a level', () => {
  assert.equal(levelName(4), 'high')
  assert.equal(levelName('5'), 'critical')
  assert.equal(levelLabel('Low'), 'Low')
  assert.equal(levelOf('informational').level, 1)
  for (const bad of [0, 6, null, undefined, '', 'severe', NaN]) assert.equal(levelOf(bad), null, String(bad))
  assert.equal(levelName(null), '')
  assert.equal(levelColor(3), 'amber')
  assert.equal(levelColor(null), 'slate')
})

test('the level filter offers each level and the ones above it', () => {
  assert.deepEqual(
    LEVEL_FILTER_OPTIONS.map((option) => option.value),
    ['', '1', '2', '3', '4', '5'],
  )
  assert.equal(LEVEL_FILTER_OPTIONS[0].label, 'Any')
  assert.equal(LEVEL_FILTER_OPTIONS[4].label, 'High+')
  assert.equal(LEVEL_FILTER_OPTIONS[5].label, 'Critical')
})

test('the counts by level come highest first and are written as a sentence', () => {
  const byLevel = { 1: 0, 2: 3, 3: 7, 4: 5, 5: 2 }
  assert.deepEqual(
    levelCounts(byLevel).map((item) => [item.name, item.count]),
    [
      ['critical', 2],
      ['high', 5],
      ['medium', 7],
      ['low', 3],
      ['informational', 0],
    ],
  )
  assert.equal(totalOf(byLevel), 17)
  assert.equal(levelsText(byLevel), '2 critical, 5 high, 7 medium, 3 low')
  assert.equal(levelsText({}), '')
  assert.equal(totalOf(undefined), 0)
})

test('the stat card turns red for high and critical, amber for medium', () => {
  assert.equal(detectionTone({ 5: 1 }), 'danger')
  assert.equal(detectionTone({ 4: 2, 1: 9 }), 'danger')
  assert.equal(detectionTone({ 3: 2 }), 'warn')
  assert.equal(detectionTone({ 1: 2, 2: 1 }), 'default')
  assert.equal(detectionTone(), 'default')
})

test('the detections of a parse report are read when the file was read with rules', () => {
  assert.equal(reportDetections({}), null)
  assert.equal(reportDetections(null), null)
  assert.deepEqual(reportDetections({ detections: { total: 3, byLevel: { 4: 3 }, rules: [{ id: 'a' }] } }), {
    total: 3,
    byLevel: { 4: 3 },
    rules: [{ id: 'a' }],
  })
  assert.deepEqual(reportDetections({ detections: { total: 0 } }), { total: 0, byLevel: {}, rules: [] })
})

test('ATT&CK tags are short words, techniques come first and link to their page', () => {
  assert.equal(tagText('attack.t1059.001'), 'T1059.001')
  assert.equal(tagText('attack.execution'), 'execution')
  assert.equal(tagText('cve.2021-44228'), 'cve.2021-44228')
  assert.deepEqual(tagChips(['attack.execution', 'attack.t1059', 'attack.t1059', '']), ['T1059', 'execution'])
  assert.equal(tagUrl('attack.t1059.001'), 'https://attack.mitre.org/techniques/T1059/001/')
  assert.equal(tagUrl('attack.t1070'), 'https://attack.mitre.org/techniques/T1070/')
  assert.equal(tagUrl('attack.execution'), '')
})

test('the chip of the rule filter names the rule, and the id when the title is not known', () => {
  assert.equal(ruleChipValue('r1', { r1: 'Security log cleared' }), 'Security log cleared')
  assert.equal(ruleChipValue('r2', {}), 'r2')
})

test('the hosts of a rule are listed, the rest counted', () => {
  assert.equal(hostsText({ hosts: [], hostCount: 0 }), '')
  assert.equal(hostsText({ hosts: ['A'], hostCount: 1 }), 'A')
  assert.equal(hostsText({ hosts: ['A', 'B', 'C', 'D'], hostCount: 4 }), 'A, B, C and 1 more')
  assert.equal(hostsText({ hosts: ['A', 'B'], hostCount: 12 }), 'A, B and 10 more')
})

test('the summary of the server is added level by level, for all sections or some', () => {
  const summary = {
    kinds: { eventlog: { detections: { 1: 0, 4: 2, 5: 1 } }, browser: { detections: { 4: 1, 3: 4 } }, commands: {} },
  }
  assert.deepEqual(summedByLevel(summary), { 1: 0, 3: 4, 4: 3, 5: 1 })
  assert.deepEqual(summedByLevel(summary, ['browser']), { 3: 4, 4: 1 })
  assert.deepEqual(summedByLevel(null), {})
  assert.equal(totalOf(summedByLevel(summary)), 8)
})

test('the rules of the Detections tab are kept from a level up', () => {
  const rules = [{ level: 5 }, { level: 3 }, { level: 1 }]
  assert.equal(rulesAtLeast(rules, '').length, 3)
  assert.equal(rulesAtLeast(rules, '3').length, 2)
  assert.equal(rulesAtLeast(rules, 5).length, 1)
  assert.deepEqual(rulesAtLeast(undefined, 2), [])
})
