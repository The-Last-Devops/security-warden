import { createPasskey, getPasskey } from './passkey.js'

let csrf = ''

async function call(method, path, body) {
  const headers = method === 'GET' ? {} : { 'Content-Type': 'application/json' }
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf
  const res = await fetch(path, { method, credentials: 'same-origin', headers, body: body ? JSON.stringify(body) : undefined })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status })
  return data
}

export const api = {
  async meta() { const m = await call('GET', '/api/meta'); csrf = m.csrf; return m },
  scan: lang => call('GET', `/api/scan?lang=${lang}`),
  rescan: lang => call('POST', `/api/scan?lang=${lang}`),
  startScan: () => call('POST', '/api/scan/start'),
  progress: lang => call('GET', `/api/scan/progress?lang=${lang}`),
  fix: (keys, lang) => call('POST', `/api/fix?lang=${lang}`, { keys }),
  undo: () => call('POST', '/api/undo'),
  ignore: (keys, days) => call('POST', '/api/ignore', { keys, days }),
  unignore: keys => call('POST', '/api/unignore', { keys }),
  logout: () => call('POST', '/api/logout'),
  passkeyStatus: () => call('GET', '/api/passkey'),
  updateStatus: () => call('GET', '/api/update'),
  setAutoUpdate: auto => call('POST', '/api/update/auto', { auto }),
  async addPasskey() {
    const opts = await call('POST', '/api/passkey/register/begin')
    return call('POST', '/api/passkey/register/finish', await createPasskey(opts))
  },
  clearPasskeys: () => call('POST', '/api/passkey/clear'),
  async loginPasskey() {
    const opts = await call('POST', '/api/passkey/login/begin')
    return call('POST', '/api/passkey/login/finish', await getPasskey(opts))
  },
}
