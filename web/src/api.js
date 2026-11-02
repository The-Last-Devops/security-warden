let csrf = ''

async function call(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: method === 'GET' ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    body: body ? JSON.stringify(body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw Object.assign(new Error(data.error || res.statusText), { status: res.status })
  return data
}

export const api = {
  async meta() { const m = await call('GET', '/api/meta'); csrf = m.csrf; return m },
  scan: lang => call('GET', `/api/scan?lang=${lang}`),
  rescan: lang => call('POST', `/api/scan?lang=${lang}`),
  fix: (keys, lang) => call('POST', `/api/fix?lang=${lang}`, { keys }),
  undo: () => call('POST', '/api/undo'),
  logout: () => call('POST', '/api/logout'),
}
