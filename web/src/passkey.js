// WebAuthn glue: the server speaks JSON with base64url fields; the browser
// API wants ArrayBuffers.
const b64uToBuf = s => {
  const pad = '='.repeat((4 - (s.length % 4)) % 4)
  const bin = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer
}
const bufToB64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

// In the macOS app (window.swApp, set by the app before the page loads) the
// app signs in with a one-time ticket instead: WKWebView has no passkeys on
// localhost.
export const inApp = () => !!window.swApp
export const passkeySupported = () => !inApp() && !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext)

function creationOptions(o) {
  const p = o.publicKey
  return {
    ...p,
    challenge: b64uToBuf(p.challenge),
    user: { ...p.user, id: b64uToBuf(p.user.id) },
    excludeCredentials: (p.excludeCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
  }
}

function requestOptions(o) {
  const p = o.publicKey
  return {
    ...p,
    challenge: b64uToBuf(p.challenge),
    allowCredentials: (p.allowCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
  }
}

function encode(cred) {
  const r = cred.response
  const out = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: { clientDataJSON: bufToB64u(r.clientDataJSON) } }
  if (r.attestationObject) {
    out.response.attestationObject = bufToB64u(r.attestationObject)
    if (r.getTransports) out.response.transports = r.getTransports()
  }
  if (r.authenticatorData) {
    out.response.authenticatorData = bufToB64u(r.authenticatorData)
    out.response.signature = bufToB64u(r.signature)
    if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle)
  }
  out.clientExtensionResults = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
  return out
}

export async function createPasskey(options) {
  return encode(await navigator.credentials.create({ publicKey: creationOptions(options) }))
}

export async function getPasskey(options) {
  return encode(await navigator.credentials.get({ publicKey: requestOptions(options) }))
}
