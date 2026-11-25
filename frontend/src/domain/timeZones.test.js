import assert from 'node:assert/strict'
import { test } from 'node:test'
import { DEFAULT_TIME_ZONE, matchZone, timeZones, zoneOf } from './timeZones.js'

test('the list starts with UTC, even when the browser leaves it out, and has each name once', () => {
  assert.deepEqual(timeZones(['Europe/Rome', 'UTC', 'Asia/Tokyo', 'Europe/Rome']), ['UTC', 'Europe/Rome', 'Asia/Tokyo'])
  assert.deepEqual(timeZones(['America/New_York']), ['UTC', 'America/New_York'])
  assert.equal(timeZones()[0], 'UTC')
})

test('a document without a zone is told in UTC', () => {
  assert.equal(zoneOf({ startHour: 8 }), DEFAULT_TIME_ZONE)
  assert.equal(zoneOf(undefined), 'UTC')
  assert.equal(zoneOf({ tz: '  ' }), 'UTC')
  assert.equal(zoneOf({ tz: 'Europe/Rome' }), 'Europe/Rome')
})

test('a name typed in any case finds its zone, and a name that is not one finds none', () => {
  const zones = ['UTC', 'Europe/Rome']
  assert.equal(matchZone(' europe/rome ', zones), 'Europe/Rome')
  assert.equal(matchZone('Mars/Base', zones), '')
  assert.equal(matchZone('', zones), '')
})
