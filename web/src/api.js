import { createPasskey, getPasskey } from './passkey.js'

let csrf = ''

async function call(method, path, body, retried = false) {
  const headers = method === 'GET' ? {} : { 'Content-Type': 'application/json' }
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf
  const res = await fetch(path, { method, credentials: 'same-origin', headers, body: body ? JSON.stringify(body) : undefined })
  const data = await res.json().catch(() => ({}))
  // The token went stale (the page was open across a restart or update):
  // fetch the current one and try once more instead of showing an error.
  if (res.status === 403 && /csrf/i.test(data.error || '') && !retried) {
    const m = await call('GET', '/api/meta')
    csrf = m.csrf
    return call(method, path, body, true)
  }
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status })
  return data
}

// Experimental checks are a per-viewer choice, kept in this browser only.
export function experimentalOn() {
  try { return localStorage.getItem('sw.experimental') === '1' } catch { return false }
}
export function setExperimental(on) {
  try { on ? localStorage.setItem('sw.experimental', '1') : localStorage.removeItem('sw.experimental') } catch {}
}
const exp = () => (experimentalOn() ? '&experimental=1' : '')

export const api = {
  async meta() { const m = await call('GET', '/api/meta'); csrf = m.csrf; return m },
  scan: lang => call('GET', `/api/scan?lang=${lang}${exp()}`),
  cached: async lang => {
    const res = await fetch(`/api/scan?lang=${lang}&cached=1${exp()}`, { credentials: 'same-origin' })
    if (res.status === 204) return null
    if (!res.ok) throw Object.assign(new Error(res.statusText), { status: res.status })
    return res.json()
  },
  rescan: lang => call('POST', `/api/scan?lang=${lang}${exp()}`),
  sources: lang => call('GET', `/api/sources?lang=${lang}`),
  startScan: () => call('POST', '/api/scan/start'),
  progress: lang => call('GET', `/api/scan/progress?lang=${lang}`),
  logs: () => call('GET', '/api/logs'),
  fix: (keys, lang) => call('POST', `/api/fix?lang=${lang}`, { keys }),
  undo: () => call('POST', '/api/undo'),
  ignore: (keys, days) => call('POST', '/api/ignore', { keys, days }),
  unignore: keys => call('POST', '/api/unignore', { keys }),
  // Feedback drafts: the server only builds a GitHub link; nothing is sent.
  feedback: key => call('GET', `/api/feedback?key=${encodeURIComponent(key)}`),
  feedbackIdea: text => call('POST', '/api/feedback/idea', { text }),
  feedbackBug: (text, log) => call('POST', '/api/feedback/bug', { text, log }),
  logout: () => call('POST', '/api/logout'),
  passkeyStatus: () => call('GET', '/api/passkey'),
  updateStatus: () => call('GET', '/api/update'),
  setAutoUpdate: auto => call('POST', '/api/update/auto', { auto }),
  setAutoApp: on => call('POST', '/api/app/auto', { on }),
  installApp: () => call('POST', '/api/app/install'),
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
