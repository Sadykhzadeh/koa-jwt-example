// Starts the server and walks the auth flow, including the ways it should
// say no. Run with `npm test`.

import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import jwt from 'jsonwebtoken'

const here = dirname(fileURLToPath(import.meta.url))
const PORT = 4921
const BASE = `http://127.0.0.1:${PORT}`
const SECRET = 'test-secret-for-the-smoke-test'

let passed = 0
let failed = 0

const check = async (name, fn) => {
  try {
    await fn()
    passed++
    console.log(`  ok    ${name}`)
  } catch (error) {
    failed++
    console.log(`  FAIL  ${name}`)
    console.log(`        ${error.message.split('\n')[0]}`)
  }
}

const assert = (condition, message) => {
  if (!condition) throw new Error(message)
}

const server = spawn(process.execPath, [join(here, '..', 'index.js')], {
  env: { ...process.env, PORT: String(PORT), JWT_SECRET: SECRET, NODE_ENV: 'test' },
  stdio: ['ignore', 'pipe', 'pipe'],
})
server.stderr.on('data', (chunk) => process.stderr.write(`[server] ${chunk}`))

const waitForServer = async () => {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const response = await fetch(`${BASE}/`)
      if (response.ok) return
    } catch {
      // not listening yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error('the server never came up')
}

const post = (path, body, headers = {}) =>
  fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })

const get = (path, headers = {}) => fetch(BASE + path, { headers })

console.log('koa-jwt-example')

try {
  await waitForServer()

  let token

  await check('login with the right credentials returns a token', async () => {
    const response = await post('/login', { username: 'azer', password: 'password1' })
    assert(response.status === 200, `status ${response.status}`)
    const body = await response.json()
    assert(typeof body.token === 'string' && body.token.length > 20, 'no token')
    token = body.token
  })

  await check('the token is signed HS256 and carries the username', () => {
    const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] })
    assert(decoded.username === 'azer', `username was ${decoded.username}`)
    assert(typeof decoded.exp === 'number', 'no expiry')
  })

  await check('a wrong password is refused', async () => {
    const response = await post('/login', { username: 'azer', password: 'wrong' })
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('an unknown user is refused', async () => {
    const response = await post('/login', { username: 'nobody', password: 'password1' })
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('a non-string password is refused rather than crashing', async () => {
    const response = await post('/login', { username: 'azer', password: { $ne: null } })
    assert(response.status === 400, `status ${response.status}`)
  })

  await check('a missing body is refused rather than crashing', async () => {
    const response = await post('/login', {})
    assert(response.status === 400, `status ${response.status}`)
  })

  await check('malformed JSON gets a clean 400, not a stack', async () => {
    const response = await post('/login', '{not json')
    assert(response.status === 400, `status ${response.status}`)
    const body = await response.json()
    assert(typeof body.error === 'string', 'no error field')
    assert(!/at \w+ \(/.test(JSON.stringify(body)), 'the body carries a stack trace')
  })

  await check('/protected works with Bearer <token>', async () => {
    const response = await get('/protected', { Authorization: `Bearer ${token}` })
    assert(response.status === 200, `status ${response.status}`)
    const body = await response.json()
    assert(body.message === 'Hello, azer!', JSON.stringify(body))
  })

  await check('/protected refuses a token with no Bearer prefix', async () => {
    // This used to be accepted: replace('Bearer ', '') leaves a header that
    // never had the prefix untouched.
    const response = await get('/protected', { Authorization: token })
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('/protected refuses a missing header', async () => {
    const response = await get('/protected')
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('/protected refuses a token signed with another key', async () => {
    const forged = jwt.sign({ username: 'azer' }, 'not-the-secret', { algorithm: 'HS256' })
    const response = await get('/protected', { Authorization: `Bearer ${forged}` })
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('/protected refuses an alg=none token', async () => {
    // The classic JWT bypass: a token that asks not to be verified.
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ username: 'azer' })).toString('base64url')
    const response = await get('/protected', { Authorization: `Bearer ${header}.${payload}.` })
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('/protected refuses an expired token', async () => {
    const expired = jwt.sign({ username: 'azer' }, SECRET, { algorithm: 'HS256', expiresIn: '-1s' })
    const response = await get('/protected', { Authorization: `Bearer ${expired}` })
    assert(response.status === 401, `status ${response.status}`)
  })

  await check('the stored passwords are hashes, not passwords', async () => {
    const source = await (await import('node:fs/promises')).readFile(join(here, '..', 'index.js'), 'utf8')
    assert(!/password:\s*'password[0-9]'/.test(source), 'a plain-text password is still in the source')
    assert(/scrypt:[0-9a-f]{32}:[0-9a-f]{64}/.test(source), 'no scrypt hash found')
  })
} finally {
  server.kill()
  await once(server, 'exit').catch(() => {})
}

console.log(`\n${passed} passed, ${failed} failed`)
process.exitCode = failed === 0 ? 0 : 1
