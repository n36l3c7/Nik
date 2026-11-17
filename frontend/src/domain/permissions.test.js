import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  ALL_PERMISSIONS,
  ROLES,
  can,
  cleanRoles,
  describeRoles,
  offeredRoles,
  permissionsOf,
  rolesOf,
  sameRoles,
  toggleRole,
} from './permissions.js'

test('roles add up to permissions, as on the server', () => {
  assert.deepEqual([...permissionsOf(['viewer'])], ['read'])
  assert.deepEqual([...permissionsOf(['analyst'])].sort(), ['automation.run', 'read', 'write'])
  assert.deepEqual([...permissionsOf(['viewer', 'audit'])].sort(), ['audit.read', 'read'])
  assert.deepEqual([...permissionsOf(['rules'])], ['rules.manage'])
  assert.deepEqual([...permissionsOf(['admin'])].sort(), [...ALL_PERMISSIONS].sort())
  assert.equal(permissionsOf(['nope']).size, 0)
  // What only an admin holds.
  const others = new Set(ROLES.filter((role) => role.id !== 'admin').flatMap((role) => role.permissions))
  assert.deepEqual(ALL_PERMISSIONS.filter((permission) => !others.has(permission)).sort(), [
    'admin',
    'automation.open',
    'content.manage',
    'incidents.configure',
  ])
})

test('roles are kept once each, in the order they are shown', () => {
  assert.deepEqual(cleanRoles(['admin', 'viewer', 'viewer', 'root']), ['viewer', 'admin'])
  assert.deepEqual(cleanRoles(null), [])
  assert.deepEqual(toggleRole(['analyst'], 'rules', true), ['analyst', 'rules'])
  assert.deepEqual(toggleRole(['analyst', 'rules'], 'analyst', false), ['rules'])
  assert.equal(sameRoles(['rules', 'analyst'], ['analyst', 'rules']), true)
  assert.equal(sameRoles(['analyst'], ['analyst', 'rules']), false)
  assert.equal(describeRoles(['rules', 'analyst']), 'Analyst, Rules')
  assert.equal(describeRoles([]), 'No role')
})

test('an account of a release before 4.0 has its single role', () => {
  assert.deepEqual(rolesOf({ role: 'admin' }), ['admin'])
  assert.deepEqual(rolesOf({ role: 'analyst', roles: ['viewer', 'audit'] }), ['viewer', 'audit'])
  assert.deepEqual(rolesOf(null), [])
})

test('can() asks the permissions the server sent, or the roles when it sent none', () => {
  const vera = { roles: ['viewer', 'audit'], permissions: ['audit.read', 'read'] }
  assert.equal(can(vera, 'read'), true)
  assert.equal(can(vera, 'write'), false)
  assert.equal(can(vera, 'write', 'audit.read'), true) // one of them is enough
  assert.equal(can({ role: 'admin' }, 'admin'), true)
  assert.equal(can({ roles: ['rules'] }, 'rules.manage'), true)
  assert.equal(can({ roles: ['rules'] }, 'read'), false)
  assert.equal(can(null, 'read'), false)
  // The server's word wins over the local table.
  assert.equal(can({ roles: ['admin'], permissions: ['read'] }, 'admin'), false)
})

test('the picker offers the roles in use now, and keeps one an account already holds', () => {
  assert.deepEqual(
    offeredRoles().map((role) => role.id),
    ['viewer', 'analyst', 'playbooks', 'connectors', 'rules', 'audit', 'admin'],
  )
  assert.deepEqual(
    offeredRoles(['dashboards']).map((role) => role.id),
    ['viewer', 'analyst', 'playbooks', 'connectors', 'rules', 'audit', 'dashboards', 'admin'],
  )
})
