import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/*
 * Every container image is named with its registry (docker.io/…).
 *
 * Docker reads a short name such as `python:3.12-slim` as docker.io, but
 * Podman resolves it through /etc/containers/registries.conf: on RHEL the
 * first registry is registry.redhat.io, which needs Red Hat credentials and
 * does not host these images, so `podman compose up --build` fails. Fully
 * qualified names build the same way with both engines.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url))
const QUALIFIED = /^[a-z0-9.-]+\.[a-z]{2,}(:\d+)?\/\S+$/ // registry host with a dot, then the path

function dockerfiles(dir) {
  const found = []
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name.startsWith('.')) continue
    const path = join(dir, name)
    if (statSync(path).isDirectory()) found.push(...dockerfiles(path))
    else if (name === 'Dockerfile' || name.endsWith('.Dockerfile')) found.push(path)
  }
  return found
}

test('every Dockerfile FROM names its registry', () => {
  const files = dockerfiles(ROOT)
  assert.ok(files.length >= 4, 'expected the backend, web, analyzer and capa Dockerfiles')
  for (const file of files) {
    const stages = new Set()
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const match = line.match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i)
      if (!match) continue
      const [, image, stage] = match
      if (!stages.has(image)) assert.match(image, QUALIFIED, `${file}: FROM ${image}`)
      if (stage) stages.add(stage)
    }
  }
})

test('every compose image names its registry', () => {
  const compose = readFileSync(join(ROOT, 'docker-compose.yml'), 'utf8')
  const images = [...compose.matchAll(/^\s+image:\s*(\S+)/gm)].map((m) => m[1])
  assert.ok(images.length > 0)
  for (const image of images) assert.match(image, QUALIFIED, `docker-compose.yml: image ${image}`)
})
