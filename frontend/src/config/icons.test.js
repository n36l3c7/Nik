import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as lucide from 'lucide-react'

/*
 * Every icon the app imports from lucide-react exists. A major release of
 * lucide renames or removes icons (1.0 dropped the brand logos); without this
 * test a missing one only shows up as a build error.
 */

const SRC = fileURLToPath(new URL('..', import.meta.url))
const IMPORT = /import\s*\{([^}]*)\}\s*from\s*'lucide-react'/g

function sources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sources(path)
    return /\.(jsx?|mjs)$/.test(name) && !name.endsWith('.test.js') ? [path] : []
  })
}

test('every lucide-react icon the app imports exists', () => {
  const missing = []
  for (const file of sources(SRC)) {
    for (const match of readFileSync(file, 'utf8').matchAll(IMPORT)) {
      for (const raw of match[1].split(',')) {
        const name = raw.trim().split(/\s+as\s+/)[0]
        if (name && !(name in lucide)) missing.push(`${name} (${file.slice(SRC.length)})`)
      }
    }
  }
  assert.deepEqual(missing, [])
})
