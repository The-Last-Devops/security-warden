<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api, experimentalOn, setExperimental } from './api.js'
import { dict } from './i18n.js'
import { inApp, passkeySupported } from './passkey.js'
import SevChip from './components/SevChip.vue'
import Segmented from './components/Segmented.vue'
import SettingsPage from './components/SettingsPage.vue'
import FixSteps from './components/FixSteps.vue'
import CodeLine from './components/CodeLine.vue'
import PerPlace from './components/PerPlace.vue'
import { perPlace, placeOf } from './fixgroup.js'
import FindingRow from './components/FindingRow.vue'
import TierBadge from './components/TierBadge.vue'
import FeedbackDialog from './components/FeedbackDialog.vue'

// Per-viewer preferences: "auto" follows the browser / system.
const pref = key => { try { return localStorage.getItem(key) } catch { return null } }
const save = (key, v) => { try { localStorage.setItem(key, v) } catch {} }
// Declared early: lang below reads it during setup.
const meta = ref(null)
const langPref = ref(pref('sw.lang') || 'auto')
const themePref = ref(pref('sw.theme') || 'auto')
const browserLang = () => ((navigator.languages || [navigator.language || 'en']).find(l => /^(vi|en)/i.test(l)) || 'en').slice(0, 2).toLowerCase()
// "Auto" in the macOS app follows the server's language (the app's web view
// reports English whatever the system uses); in a browser, the browser's.
const lang = computed(() => (langPref.value === 'auto' ? (inApp() && meta.value?.lang) || browserLang() : langPref.value))
const t = computed(() => dict[lang.value] || dict.en)
function applyTheme(v) { const r = document.documentElement; if (v === 'auto') delete r.dataset.theme; else r.dataset.theme = v }
applyTheme(themePref.value)
document.documentElement.lang = lang.value
watch(themePref, v => { save('sw.theme', v); applyTheme(v) })
// The header's quick switch: from what is shown now to the other one.
const systemDark = () => globalThis.matchMedia?.('(prefers-color-scheme: dark)').matches
const shownDark = computed(() => (themePref.value === 'auto' ? systemDark() : themePref.value === 'dark'))
const flipTheme = () => { themePref.value = shownDark.value ? 'light' : 'dark' }
watch(langPref, v => save('sw.lang', v))
watch(lang, l => { document.documentElement.lang = l; if (meta.value) load() })

const data = ref(null)
const busy = ref(false)
const signedOut = ref(false)
const cat = ref('all')
const sheet = ref(null)
const toast = ref('')
const toastErr = ref(false)
const toastAction = ref(null) // { label, run } shown as a button in the toast
function say(msg, isError = false, action = null) {
  toast.value = msg; toastErr.value = isError; toastAction.value = action
  if (!isError) setTimeout(() => { if (toast.value === msg) { toast.value = ''; toastAction.value = null } }, action ? 8000 : 5000)
}
const fail = e => { if (e.status === 401) signedOut.value = true; else say(`${t.value.error}: ${e.message}`, true) }

const codeCats = ['code_secrets', 'code_deps']
const categories = ['secrets', 'exposure', 'settings', 'persistence', 'ai', 'devtools', 'software', ...codeCats]
const sevOrder = ['critical', 'high', 'medium', 'low', 'info']

async function load(force = false) {
  if (force) return rescan()
  busy.value = true
  try {
    // Show the last scan right away; with none yet, scan with the progress modal.
    const cached = await api.cached(lang.value)
    if (cached) { data.value = cached; return }
    busy.value = false
    return rescan(true)
  } catch (e) { fail(e) } finally { if (!prog.value) busy.value = false }
}

// Rescan with visible progress: start, poll which sources are done, then
// load the result and say what changed.
const prog = ref(null)
const sleep = ms => new Promise(r => setTimeout(r, ms))
async function rescan(first = false) {
  if (prog.value) return
  // Compared per kind of problem, like the list: a file moving does not count.
  const before = new Set(findings.value.map(f => f.rule_id))
  busy.value = true
  prog.value = { done: [], pending: [], total: 0 }
  // Show progress for at least 3 seconds: a scan that flashes by looks
  // like it failed. The bar never runs ahead of the real scan.
  const MIN_MS = 3000
  const started = performance.now()
  try {
    await api.startScan()
    for (;;) {
      await sleep(120)
      const p = await api.progress(lang.value)
      const elapsed = performance.now() - started
      const shown = Math.min(p.done.length, Math.floor((p.total * elapsed) / MIN_MS))
      prog.value = { ...p, done: p.done.slice(0, shown), pending: [...p.done.slice(shown).map(d => d.label), ...p.pending] }
      // Sources that timed out never report done: the scan is over when
      // the server says so, not when every source has finished.
      if (!p.running && elapsed >= MIN_MS) break
    }
    data.value = await api.scan(lang.value)
    const after = new Set(findings.value.map(f => f.rule_id))
    let added = 0, gone = 0
    for (const k of after) if (!before.has(k)) added++
    for (const k of before) if (!after.has(k)) gone++
    const late = (data.value.sources || []).filter(s => s.state === 'error' && s.detail === 'timed out').length
    if (late) say(t.value.scanTimedOut(late), true, { label: t.value.scanLog, run: () => go('settings/logs') })
    else if (!first) say(t.value.scanDone(after.size, added, gone))
  } catch (e) { fail(e) } finally { prog.value = null; busy.value = false }
}
const progPct = computed(() => (prog.value?.total ? Math.round((prog.value.done.length / prog.value.total) * 100) : 4))

// Passkeys
const pk = ref({ count: 0, available: false, localhost: '' })
const canPasskey = computed(() => pk.value.available && passkeySupported())
async function refreshPasskey() { try { pk.value = await api.passkeyStatus() } catch {} }
async function signInPasskey() {
  busy.value = true
  try { await api.loginPasskey(); signedOut.value = false; meta.value = await api.meta(); load() }
  catch (e) { if (e.name === 'NotAllowedError') say(t.value.passkeyCancelled); else say(`${t.value.error}: ${e.message}`, true) }
  finally { busy.value = false }
}
async function addPasskey() {
  try { const r = await api.addPasskey(); pk.value.count = r.count; say(t.value.passkeyAdded) }
  catch (e) { if (e.status === 401) signedOut.value = true; else if (e.name === 'NotAllowedError') say(t.value.passkeyCancelled); else say(`${t.value.error}: ${e.message}`, true) }
}
// First sign-in without a passkey: offer one right away (once per browser).
// First sign-in: a passkey is required before the dashboard opens.
const onboarding = ref(false)
const onbFailed = ref(false)
async function onbAdd() {
  try {
    const r = await api.addPasskey()
    pk.value.count = r.count
    onboarding.value = false
    say(t.value.passkeyAdded)
  } catch (e) {
    if (e.status === 401) { onboarding.value = false; signedOut.value = true; return }
    onbFailed.value = true
    if (e.name !== 'NotAllowedError') say(`${t.value.error}: ${e.message}`, true)
  }
}

async function clearPasskeys() { try { await api.clearPasskeys(); pk.value.count = 0; say(t.value.passkeysRemoved) } catch (e) { fail(e) } }

onMounted(async () => {
  await refreshPasskey()
  try { meta.value = await api.meta() } catch (e) { if (e.status === 401) { signedOut.value = true; return } }
  if (canPasskey.value && !pk.value.count) onboarding.value = true
  load()
})

const findings = computed(() => data.value?.findings || [])
const ignored = computed(() => data.value?.ignored || [])
const passedList = computed(() => data.value?.passed || [])
const passedByCat = computed(() => {
  const by = {}
  for (const p of passedList.value) (by[p.category] ||= []).push(p)
  return categories.filter(c => by[c]).map(c => ({ cat: c, items: by[c] }))
})
// In one group: what was looked at and what already passes there.
const catPassed = computed(() => passedList.value.filter(p => p.category === cat.value))
// Counted per kind of problem (rule), the same way the list groups them.
const counts = computed(() => { const c = {}; for (const id of new Set(findings.value.map(f => f.category + '\u0000' + f.rule_id))) { const k = id.split('\u0000')[0]; c[k] = (c[k] || 0) + 1 } return c })
const groupsAll = computed(() => new Set(findings.value.map(f => f.rule_id)).size)
const sevCounts = computed(() => { const c = {}; for (const f of findings.value) c[f.severity] = (c[f.severity] || 0) + 1; return c })
const worst = computed(() => {
  const w = {}
  for (const f of findings.value) if (w[f.category] === undefined || sevOrder.indexOf(f.severity) < sevOrder.indexOf(w[f.category])) w[f.category] = f.severity
  return w
})
// Groups with problems first (worst severity, then most problems); clean ones last.
const sortedCategories = computed(() => [...categories].sort((a, b) => {
  const ra = worst.value[a] ? sevOrder.indexOf(worst.value[a]) : 99
  const rb = worst.value[b] ? sevOrder.indexOf(worst.value[b]) : 99
  return ra - rb || (counts.value[b] || 0) - (counts.value[a] || 0) || categories.indexOf(a) - categories.indexOf(b)
}))
const worstDot = { critical: 'bg-crit', high: 'bg-high', medium: 'bg-med', low: 'bg-low', info: 'bg-info' }
const worstText = { critical: 'text-crit', high: 'text-high', medium: 'text-med', low: 'text-low', info: 'text-info' }
const groups = computed(() => {
  const by = new Map()
  for (const f of findings.value) {
    if (cat.value !== 'all' && f.category !== cat.value) continue
    if (!by.has(f.rule_id)) by.set(f.rule_id, { first: f, rest: [], fixable: [] })
    else by.get(f.rule_id).rest.push(f)
    if (f.can_fix) by.get(f.rule_id).fixable.push(f)
  }
  return [...by.values()].sort((a, b) => sevOrder.indexOf(a.first.severity) - sevOrder.indexOf(b.first.severity))
})
// On "All", the most important group becomes the single "next step" card.
const nextGroup = computed(() => (cat.value === 'all' ? groups.value[0] || null : null))
const nextPP = computed(() => (nextGroup.value ? perPlace([nextGroup.value.first, ...nextGroup.value.rest]) : null))
const listGroups = computed(() => (nextGroup.value ? groups.value.slice(1) : groups.value))
// "By repo" view: everything about one repository together; problems of the
// machine itself come first under its own heading.
const view = ref('sev')
const repoOf = f => f.repo || ''
const repoSections = computed(() => {
  const by = new Map()
  for (const f of findings.value) {
    if (cat.value !== 'all' && f.category !== cat.value) continue
    const repo = scopeOf(f.category) === 'code' ? repoOf(f) || t.value.otherRepos : ''
    if (!by.has(repo)) by.set(repo, new Map())
    const rules = by.get(repo)
    if (!rules.has(f.rule_id)) rules.set(f.rule_id, { first: f, rest: [], fixable: [] })
    else rules.get(f.rule_id).rest.push(f)
    if (f.can_fix) rules.get(f.rule_id).fixable.push(f)
  }
  const rank = g => sevOrder.indexOf(g.first.severity)
  return [...by.entries()].map(([repo, rules]) => ({ repo, groups: [...rules.values()].sort((a, b) => rank(a) - rank(b)) }))
    .sort((a, b) => (a.repo === '' ? -1 : b.repo === '' ? 1 : rank(a.groups[0]) - rank(b.groups[0]) || b.groups.length - a.groups.length))
})
const sections = computed(() => sevOrder.map(sev => ({ sev, groups: listGroups.value.filter(g => g.first.severity === sev) })).filter(x => x.groups.length))
const nextOpen = ref(false)
const scoreColor = computed(() => { const sc = data.value?.scan.score ?? 0; return sc >= 75 ? 'var(--color-ok)' : sc >= 50 ? 'var(--color-med)' : 'var(--color-crit)' })
const RING = 2 * Math.PI * 30
// Two scopes: the machine itself, and the code (repositories) on it.
const scopeOf = c => (codeCats.includes(c) ? 'code' : 'machine')
const colorOf = sc => (sc >= 75 ? 'var(--color-ok)' : sc >= 50 ? 'var(--color-med)' : sc >= 26 ? 'var(--color-high)' : 'var(--color-crit)')
const scopes = computed(() => ['machine', 'code'].map(id => {
  const fs = findings.value.filter(f => scopeOf(f.category) === id)
  const kinds = new Set(fs.map(f => f.rule_id)).size
  const worstSev = sevOrder.find(sv => fs.some(f => f.severity === sv))
  const score = data.value?.scan[id === 'machine' ? 'score_machine' : 'score_code'] ?? 0
  return { id, score, kinds, worstSev, color: colorOf(score), cats: sortedCategories.value.filter(c => scopeOf(c) === id) }
}))
const safeFixes = computed(() => findings.value.filter(f => f.can_fix))
// Points earned by fixing every safe item (each rule counts once).
const passedN = computed(() => (data.value?.scan.passed || []).length)
const window = globalThis.window
const fmtTime = iso => (iso ? new Date(iso).toLocaleTimeString(lang.value, { hour: '2-digit', minute: '2-digit' }) : '')
const fmtDate = iso => new Date(iso).toLocaleDateString(lang.value, { day: 'numeric', month: 'short', year: 'numeric' })
const listTitle = computed(() => (cat.value === 'all' ? t.value.issuesTitle : cat.value === 'ignored' ? t.value.ignoredTitle : cat.value === 'safe' ? t.value.safeTitle : t.value[cat.value]))

const themeOptions = computed(() => [{ value: 'auto', label: t.value.auto }, { value: 'light', label: t.value.light }, { value: 'dark', label: t.value.dark }])
const langOptions = computed(() => [{ value: 'auto', label: t.value.auto }, { value: 'en', label: 'EN' }, { value: 'vi', label: 'VI' }])
const stCls = { ok: 'bg-ok-bg text-ok', issues: 'bg-high-bg text-high', skipped: 'bg-info-bg text-info', error: 'bg-crit-bg text-crit' }

function askFix(list) { sheet.value = list.map(f => ({ f, on: true })) }
const sheetOn = computed(() => (sheet.value || []).filter(x => x.on).length)
async function applyFix() {
  const keys = sheet.value.filter(x => x.on).map(x => x.f.key)
  sheet.value = null
  if (!keys.length) return
  busy.value = true
  try {
    const r = await api.fix(keys, lang.value)
    const ok = r.results.filter(x => x.ok).length
    const bad = r.results.filter(x => !x.ok)
    if (bad.length) say(`${t.value.done(ok)} ${t.value.failed}: ${bad[0].error}`, true); else say(t.value.done(ok))
    await load(true)
  } catch (e) { fail(e) } finally { busy.value = false }
}
async function undo() {
  try {
    const r = await api.undo()
    if (r.error) say(`${t.value.failed}: ${r.error}`, true); else say(r.undone ? t.value.undone(r.undone) : t.value.nothingUndo)
    if (r.undone) await load(true)
  } catch (e) { fail(e) }
}
// Hiding always asks first: what, for how long, and where to get it back.
const hideAsk = ref(null) // { list, days }
function askHide(list) { hideAsk.value = { list, days: 7 } }
const hideUntil = computed(() => (hideAsk.value ? fmtDate(new Date(Date.now() + hideAsk.value.days * 864e5).toISOString()) : ''))
async function confirmHide() { const h = hideAsk.value; hideAsk.value = null; await ignoreFindings(h.list, h.days) }
// Hidden findings grouped per kind of problem, for the list's last section.
const hiddenGroups = computed(() => {
  const by = new Map()
  for (const x of ignored.value) {
    if (!by.has(x.rule_id)) by.set(x.rule_id, { first: x, keys: [] })
    by.get(x.rule_id).keys.push(x.key)
  }
  return [...by.values()]
})
async function ignoreFindings(list, days) {
  const keys = list.map(f => f.key)
  try {
    const r = await api.ignore(keys, days)
    say(t.value.ignoredDone(r.ignored), false, { label: t.value.restore, run: () => restore(keys) })
    await load()
  } catch (e) { fail(e) }
}
async function restore(keys) { try { await api.unignore(keys); say(t.value.restored); await load() } catch (e) { fail(e) } }
async function logout() { try { await api.logout() } catch {} ; signedOut.value = true }
// Settings is a full page (☰ menu), in the URL hash so Back works: #settings/<tab>.
// #settings/<tab> opens one sub-page of the settings.
const hashParts = () => location.hash.slice(1).split('/')
// #logs (older links) is the log sub-page.
const pageOf = () => (['settings', 'logs'].includes(hashParts()[0]) ? 'settings' : '')
const tabOf = () => (hashParts()[0] === 'logs' ? 'logs' : hashParts()[1] || '')
const page = ref(pageOf())
const settingsTab = ref(tabOf())
window.addEventListener('hashchange', () => { page.value = pageOf(); settingsTab.value = tabOf(); window.scrollTo({ top: 0 }) })
function go(p) { moreOpen.value = false; watchOpen.value = false; if (p) location.hash = p; else history.pushState(null, '', location.pathname + location.search); page.value = p.split('/')[0]; settingsTab.value = p.split('/')[1] || '' }
const moreOpen = ref(false)
// The macOS app, for those who installed before it existed (meta.app_hint).
const appHintOff = ref(pref('sw.appHint') === 'off')
const appHintShown = computed(() => !!meta.value?.app_hint && !inApp() && !appHintOff.value && !page.value)
function hideAppHint() { appHintOff.value = true; save('sw.appHint', 'off') }
// Feedback dialog: { key } for a wrong finding, { key: '' } for a new idea.
const feedbackAsk = ref(null)
// Experimental checks: per viewer; the cached scan is evaluated again with them.
const experimental = ref(experimentalOn())
watch(experimental, v => { setExperimental(v); if (meta.value) load() })
const watchOpen = ref(false)
const upd = ref(null)
async function refreshUpdate() { try { upd.value = await api.updateStatus() } catch {} }
async function toggleAutoApp() {
  if (!upd.value) return
  try { const r = await api.setAutoApp(!upd.value.auto_app); upd.value.auto_app = r.auto_app } catch (e) { fail(e) }
}
const installingApp = ref(false)
async function installApp() {
  installingApp.value = true
  try { await api.installApp(); say(t.value.appInstalled); hideAppHint() } catch (e) { fail(e) } finally { installingApp.value = false }
}
async function toggleAuto() {
  if (!upd.value) return
  try { const r = await api.setAutoUpdate(!upd.value.auto); upd.value.auto = r.auto } catch (e) { fail(e) }
}
onMounted(refreshUpdate)
function onKey(e) { if (e.key === 'Escape') { if (page.value && !sheet.value && !feedbackAsk.value && !moreOpen.value) go(''); sheet.value = null; watchOpen.value = false; moreOpen.value = false; feedbackAsk.value = null } }
onMounted(() => document.addEventListener('click', () => { watchOpen.value = false; moreOpen.value = false }))
// On the document: Esc works with nothing focused too.
onMounted(() => document.addEventListener('keydown', onKey))
</script>

<template>
  <!-- signed out -->
  <div v-if="signedOut" class="mx-auto mt-[16vh] max-w-md px-4">
    <section class="panel rise grid gap-4 p-8 text-center">
      <svg class="mx-auto" width="40" height="44" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" fill="var(--color-accent)" /></svg>
      <h1 class="text-[22px] font-extrabold tracking-[.04em] uppercase">Security Warden</h1>
      <button v-if="canPasskey && pk.count" class="mx-auto inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-[15px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="signInPasskey">
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="4" fill="none" stroke="currentColor" stroke-width="2" /><path d="M2 21c0-3.9 3.1-7 7-7 1.5 0 2.9.5 4 1.3M17 11a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm0 6v5m0-2h2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
        {{ t.signInPasskey }}
      </button>
      <button v-else-if="inApp()" class="mx-auto inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-3 text-[15px] font-semibold text-accent-ink hover:brightness-110" @click="window.swApp.signIn()">{{ t.signInAgain }}</button>
      <p v-else-if="pk.count && !pk.available" class="text-[14px] text-muted">{{ t.passkeyNeedsLocalhost }} <a class="font-mono text-accent underline" :href="pk.localhost">{{ pk.localhost }}</a></p>
      <p class="text-[14px] text-muted">{{ inApp() ? t.signedOutApp : pk.count ? t.signInHelp : t.signedOut }}</p>
    </section>
  </div>

  <div v-else class="min-h-screen">
    <!-- top bar -->
    <header class="border-b border-line">
      <div class="mx-auto flex max-w-[1280px] flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3.5 sm:px-6">
        <button class="flex items-center gap-2.5 rounded-lg text-[15px] font-extrabold tracking-[.06em] uppercase hover:text-accent" :title="t.home" @click="cat = 'all'; window.scrollTo({ top: 0, behavior: 'smooth' })">
          <svg width="20" height="22" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" fill="var(--color-accent)" /></svg>
          Security Warden
        </button>
        <button v-if="upd?.current" class="num -ml-2 inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-[12px] font-semibold ring-1"
          :class="upd.available ? 'bg-crit-bg text-crit ring-crit/40' : 'bg-ok-bg text-ok ring-ok/30'"
          :title="upd.available ? t.newVersion(upd.latest) : t.upToDate" @click.stop="go('settings/updates')">
          <i class="h-1.5 w-1.5 rounded-full" :class="upd.available ? 'bg-crit' : 'bg-ok'" />{{ upd.current }}
        </button>
        <div v-if="data" class="relative">
          <button class="flex items-center gap-2 rounded-lg px-2 py-1 text-[13px] text-muted hover:bg-panel2 hover:text-fg" :aria-expanded="watchOpen" @click.stop="watchOpen = !watchOpen; moreOpen = false">
            <i class="h-2 w-2 rounded-full" :class="data.watching ? 'bg-ok shadow-[0_0_0_4px_var(--color-ok-bg)]' : 'bg-muted/60'" />
            <span class="font-semibold" :class="data.watching ? 'text-fg/85' : ''">{{ data.watching ? t.watching : t.notWatching }}</span>
            <span class="hidden lg:inline">· {{ data.scan.host }} · {{ t.lastScan(fmtTime(data.scanned_at)) }}</span>
            <svg width="12" height="12" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.5" /><path d="M8 7.2v4M8 4.8v.1" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" /></svg>
          </button>
          <div v-if="watchOpen" class="rise absolute left-0 z-30 mt-2 grid w-[min(24rem,calc(100vw-2rem))] gap-3 rounded-2xl border border-line bg-panel p-5 shadow-2xl" @click.stop>
            <h2 class="text-[16px] font-bold">{{ data.watching ? t.watchTitle : t.notWatchingTitle }}</h2>
            <ul v-if="data.watching" class="grid gap-2.5 text-[14px] leading-snug">
              <li v-for="(line, i) in t.watchLines" :key="i" class="flex gap-2.5"><span class="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-ok-bg text-[11px] font-bold text-ok">✓</span><span>{{ line }}</span></li>
            </ul>
            <p v-else class="text-[14px] leading-relaxed">{{ t.notWatchingBody }}</p>
            <p v-if="!data.watching" class="rounded-lg bg-panel2 px-3 py-2 font-mono text-[13px] ring-1 ring-line">security-warden start</p>
            <p class="border-t border-line pt-3 text-[13px] text-muted">{{ data.watching ? t.watchNext(fmtTime(new Date(new Date(data.scanned_at).getTime() + 30 * 60000).toISOString())) + ' ' + t.watchStop : t.local }}</p>
          </div>
        </div>
        <div class="ml-auto flex items-center gap-2">
          <select v-model="langPref" :aria-label="t.language" :title="t.language"
            class="h-10 cursor-pointer rounded-xl border border-line bg-panel2 px-3 text-[14px] font-semibold text-muted hover:text-fg focus:outline-none focus:ring-2 focus:ring-accent">
            <option value="auto">{{ t.auto }}</option>
            <option value="vi">Tiếng Việt</option>
            <option value="en">English</option>
          </select>
          <button class="grid h-10 w-10 place-items-center rounded-xl border border-line bg-panel2 text-muted hover:text-fg" :aria-label="shownDark ? t.light : t.dark" :title="shownDark ? t.light : t.dark" @click="flipTheme">
            <svg v-if="shownDark" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></svg>
            <svg v-else width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" /></svg>
          </button>
        <div class="relative">
          <button class="grid h-10 w-10 place-items-center rounded-xl border border-line bg-panel2 text-muted hover:text-fg" :aria-label="t.more" aria-haspopup="menu" :aria-expanded="moreOpen" @click.stop="moreOpen = !moreOpen; watchOpen = false">
            <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" /></svg>
          </button>
          <div v-if="moreOpen" class="rise absolute right-0 z-30 mt-2 grid w-60 gap-0.5 rounded-2xl border border-line bg-panel p-1.5 shadow-2xl" role="menu" @click.stop>
            <button role="menuitem" class="flex items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[15px] font-semibold hover:bg-panel2" @click="go('settings')">
              <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" /></svg>{{ t.settings }}
            </button>
            <button role="menuitem" class="flex items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[15px] font-semibold hover:bg-panel2" @click="go('settings/logs')">
              <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>{{ t.scanLog }}
            </button>
            <button role="menuitem" class="flex items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[15px] font-semibold hover:bg-panel2" @click="go('settings/rules')">
              <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h10" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>{{ t.rulesSources }}
            </button>
            <button role="menuitem" class="flex items-center gap-3 rounded-xl px-3 py-2.5 text-left text-[15px] font-semibold hover:bg-panel2" @click="moreOpen = false; feedbackAsk = { key: '', bug: true }">
              <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M8 6a4 4 0 0 1 8 0M6 10h12v4a6 6 0 0 1-12 0zM12 10v10M3 13h3M18 13h3M4 7l2.5 2.5M20 7l-2.5 2.5M4 20l2.5-2.5M20 20l-2.5-2.5" /></svg>{{ t.reportBug }}
            </button>
          </div>
        </div>
        </div>
      </div>
    </header>

    <SettingsPage v-if="page === 'settings'" :tab="settingsTab" :ui-lang="lang" v-model:theme="themePref" v-model:lang="langPref" v-model:experimental="experimental" :t="t" :theme-options="themeOptions" :lang-options="langOptions"
      :pk="pk" :can-passkey="canPasskey" :upd="upd" :busy="busy" :checked-at="upd?.checked && new Date(upd.checked).getFullYear() > 2000 ? fmtTime(upd.checked) : ''"
      @close="go('')" @add-passkey="addPasskey()" @clear-passkeys="clearPasskeys()"
      @toggle-auto="toggleAuto" @toggle-auto-app="toggleAutoApp" @undo="undo()" @logout="logout()" @bug="feedbackAsk = { key: '', bug: true }" />
    <template v-else>
    <!-- macOS without the app: how to get it (once dismissed, gone for good) -->
    <div v-if="appHintShown" class="mx-auto mt-4 max-w-[1280px] px-4 sm:px-6">
      <div class="grid gap-2 rounded-xl bg-accent-soft px-4 py-3 text-[14px] ring-1 ring-accent/30 sm:flex sm:flex-wrap sm:items-center sm:gap-x-3">
        <span class="font-semibold text-accent">{{ t.appHintTitle }}</span>
        <span class="text-muted">{{ meta.app_hint === 'brew' ? t.appHintBrew : t.appHintDmg }}</span>
        <button v-if="meta.app_hint === 'brew'" class="justify-self-start rounded-lg bg-accent px-3.5 py-1.5 text-[13.5px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-60" :disabled="installingApp" @click="installApp">{{ installingApp ? t.appInstalling : t.appInstall }}</button>
        <CodeLine v-if="meta.app_hint === 'brew'" class="min-w-0 sm:flex-1" code="brew install --cask the-last-devops/security-warden/security-warden-app" :t="t" />
        <a v-else href="https://github.com/The-Last-Devops/security-warden/releases/latest" target="_blank" rel="noopener noreferrer" class="font-semibold text-accent hover:underline">{{ t.appHintDownload }} ↗</a>
        <button class="justify-self-start rounded-lg px-2 py-1 text-[13px] font-semibold text-muted hover:text-fg sm:ml-auto" @click="hideAppHint">{{ t.appHintLater }}</button>
      </div>
    </div>
    <div v-if="upd && upd.available" class="mx-auto mt-4 flex max-w-[1280px] flex-wrap items-center gap-x-3 gap-y-1 px-4 sm:px-6">
      <div class="flex w-full flex-wrap items-center gap-x-3 gap-y-1 rounded-xl bg-accent-soft px-4 py-2.5 text-[14px] ring-1 ring-accent/30">
        <span class="font-semibold text-accent">{{ t.newVersion(upd.latest) }}</span>
        <span class="text-muted">{{ upd.method === 'brew' ? t.updateHowBrew : t.updateHowManual }}</span>
        <span v-if="upd.method === 'brew'" class="flex flex-wrap gap-2">
          <code class="rounded-md bg-panel px-2 py-0.5 font-mono text-[12.5px] ring-1 ring-line">security-warden update</code>
          <code class="rounded-md bg-panel px-2 py-0.5 font-mono text-[12.5px] ring-1 ring-line">brew upgrade security-warden</code>
        </span>
      </div>
    </div>
    <div class="mx-auto grid max-w-[1280px] gap-5 px-4 py-5 sm:px-6 lg:grid-cols-[290px_1fr]">
      <!-- left: score, counts, groups -->
      <aside class="grid content-start gap-5">
        <section class="panel grid gap-4 p-5">
          <div v-for="(sc, k) in scopes" :key="sc.id" class="grid grid-cols-[56px_1fr] items-center gap-3" :class="k ? 'border-t border-line pt-4' : ''">
            <svg width="56" height="56" viewBox="0 0 76 76" role="img" :aria-label="`${t['scope_' + sc.id]}: ${sc.score}/100`">
              <circle cx="38" cy="38" r="31" fill="none" stroke="var(--color-line)" stroke-width="7" />
              <circle cx="38" cy="38" r="31" fill="none" :stroke="sc.color" stroke-width="7" stroke-linecap="round"
                :stroke-dasharray="`${(RING * Math.max(sc.score, 1)) / 100} ${RING}`" transform="rotate(-90 38 38)" class="transition-all duration-700" />
              <text x="38" y="46" text-anchor="middle" font-size="24" font-weight="800" fill="var(--color-fg)" font-family="Plus Jakarta Sans, sans-serif">{{ sc.score }}</text>
            </svg>
            <button class="min-w-0 text-left" @click="cat = sc.cats[0] && sc.kinds ? sc.cats[0] : cat">
              <span class="caps flex items-center gap-1.5"><svg v-if="sc.id === 'machine'" width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" class="shrink-0"><rect x="4" y="5" width="16" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="2" /><path d="M2 19h20" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg><svg v-else width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" class="shrink-0"><path d="m8 7-5 5 5 5M16 7l5 5-5 5M13.5 5l-3 14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" /></svg>{{ t['scope_' + sc.id] }}</span>
              <span class="block text-[15.5px] leading-tight font-bold" :style="{ color: sc.color }">{{ data ? (sc.kinds ? t.toFix(sc.kinds) : t.allGood) : t.scanning }}</span>
              <span class="mt-0.5 block text-[12.5px] text-muted">{{ t['scope_' + sc.id + '_help'] }}</span>
            </button>
          </div>
          <button v-if="safeFixes.length" class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="askFix(safeFixes)">{{ t.fixSafe(safeFixes.length) }}</button>
          <div class="flex items-center gap-2">
            <button class="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-line bg-panel2 px-4 py-2.5 text-[14px] font-semibold hover:border-accent hover:text-accent disabled:opacity-50" :disabled="busy" @click="load(true)">
              <svg :class="busy ? 'animate-spin' : ''" width="15" height="15" viewBox="0 0 16 16" aria-hidden="true"><path d="M13.5 8A5.5 5.5 0 1 1 8 2.5c1.6 0 3 .7 4 1.7M12.5 1.5v3h-3" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
              {{ busy ? t.scanning : t.rescan }}
            </button>
          </div>
        </section>

        <nav class="panel p-2" :aria-label="t.groups">
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px] font-semibold"
            :class="cat === 'all' ? 'bg-accent-soft text-accent' : 'hover:bg-panel2'" @click="cat = 'all'">
            {{ t.all }} <span class="num">{{ groupsAll }}</span>
          </button>
          <template v-for="sc in scopes" :key="sc.id">
            <div class="caps flex items-center gap-1.5 px-3 pt-3 pb-1"><svg v-if="sc.id === 'machine'" width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" class="shrink-0"><rect x="4" y="5" width="16" height="11" rx="2" fill="none" stroke="currentColor" stroke-width="2" /><path d="M2 19h20" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg><svg v-else width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" class="shrink-0"><path d="m8 7-5 5 5 5M16 7l5 5-5 5M13.5 5l-3 14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" /></svg>{{ t['scope_' + sc.id] }}</div>
            <button v-for="c in sc.cats" :key="c" class="flex w-full items-center gap-2.5 rounded-xl px-3 py-2.5 text-left text-[15px]"
              :class="cat === c ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = c">
              <i class="h-2 w-2 shrink-0 rounded-full" :class="counts[c] ? worstDot[worst[c]] : 'bg-line'" />
              {{ t[c] }}
              <span class="num ml-auto font-bold" :class="counts[c] ? worstText[worst[c]] : 'text-muted/50'">{{ counts[c] || 0 }}</span>
            </button>
          </template>
          <div class="caps px-3 pt-3 pb-1">{{ t.other }}</div>
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px]"
            :class="cat === 'safe' ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = 'safe'">
            <span class="flex items-center gap-2"><span class="text-ok">✓</span>{{ t.safeView }}</span> <span class="num font-bold text-ok">{{ passedList.length }}</span>
          </button>
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px]"
            :class="cat === 'ignored' ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = 'ignored'">
            {{ t.ignoredView }} <span class="num text-muted">{{ ignored.length }}</span>
          </button>
        </nav>
        <button class="flex items-center gap-2 justify-self-start rounded-lg px-3 py-1.5 text-[13px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="go('settings/rules')">
          <svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true" class="shrink-0"><path d="M5 4h11l3 3v13H5zM9 10h6M9 14h6M9 18h4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" /></svg>
          {{ t.rulesSources }}
        </button>
      </aside>

      <!-- right: list -->
      <main class="panel min-w-0 self-start">
        <div class="flex flex-wrap items-center gap-3 border-b border-line px-5 py-4">
          <h1 class="text-[19px] font-bold">{{ listTitle }}</h1>
          <span v-if="!['ignored', 'safe'].includes(cat)" class="num rounded-full bg-panel2 px-2.5 py-0.5 text-[13px] font-bold text-muted ring-1 ring-line">{{ groups.length }}</span>
          <div v-if="!['ignored', 'safe'].includes(cat)" class="ml-auto inline-flex rounded-[10px] bg-panel2 p-0.5 ring-1 ring-line" role="group">
            <button v-for="v in ['sev', 'repo']" :key="v" class="rounded-lg px-3 py-1 text-[13px] font-semibold" :class="view === v ? 'bg-panel text-fg shadow-sm ring-1 ring-line' : 'text-muted hover:text-fg'" :aria-pressed="view === v" @click="view = v">{{ v === 'sev' ? t.bySeverity : t.byRepo }}</button>
          </div>
        </div>

        <!-- safe: what already passes -->
        <div v-if="cat === 'safe'">
          <p class="border-b border-line bg-ok-bg px-5 py-3 text-[14.5px] font-semibold text-ok">{{ t.safeNote(passedList.length) }}</p>
          <section v-for="g in passedByCat" :key="g.cat" class="border-b border-line px-5 py-4 last:border-b-0">
            <h2 class="caps mb-2.5">{{ t[g.cat] }} · <span class="num">{{ g.items.length }}</span></h2>
            <ul class="grid gap-x-6 gap-y-2 sm:grid-cols-2">
              <li v-for="p in g.items" :key="p.rule_id" class="flex items-start gap-2.5 text-[14.5px]">
                <span class="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-ok-bg text-[12px] font-bold text-ok">✓</span>
                <span>{{ p.label }}<TierBadge v-if="p.tier" class="ml-2 align-[2px]" :tier="p.tier" :t="t" /></span>
              </li>
            </ul>
          </section>
        </div>

        <!-- ignored -->
        <div v-else-if="cat === 'ignored'">
          <p v-if="!ignored.length" class="px-5 py-10 text-center text-muted">{{ t.nothingIgnored }}</p>
          <div v-for="x in ignored" :key="x.key" class="grid grid-cols-[1fr_auto] items-center gap-4 border-t border-line px-5 py-3 first:border-t-0">
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2"><SevChip :sev="x.severity" :label="t.sev[x.severity]" /><span class="text-[15px] font-semibold break-words">{{ x.title }}</span></div>
              <div class="mt-0.5 text-[13px] text-muted">{{ x.until ? t.until(fmtDate(x.until)) : t.forever }} · <span class="font-mono text-[12px]">{{ x.rule_id }}</span></div>
            </div>
            <button class="rounded-[10px] border border-line px-3 py-1.5 text-[13px] font-semibold hover:bg-panel2" @click="restore([x.key])">{{ t.restore }}</button>
          </div>
        </div>

        <!-- issues -->
        <div v-else>
          <p v-if="data && !groups.length && cat !== 'all'" class="mx-5 mt-5 rounded-xl bg-ok-bg px-5 py-3.5 text-[15px] font-semibold text-ok">{{ t.noIssues }}</p>
          <p v-if="data && !groups.length && cat === 'all'" class="mx-5 my-6 rounded-xl bg-ok-bg px-5 py-4 text-center text-[15px] font-semibold text-ok">{{ t.allClear }}</p>
          <article v-if="nextGroup && view === 'sev'" class="m-3 mb-1 overflow-hidden rounded-2xl bg-panel ring-1 ring-line">
            <div class="flex flex-wrap items-center gap-2 px-5 py-2.5"
              :class="{ critical: 'bg-crit-bg text-crit', high: 'bg-high-bg text-high', medium: 'bg-med-bg text-med', low: 'bg-low-bg text-low', info: 'bg-panel2 text-muted' }[nextGroup.first.severity]">
              <span class="text-[12.5px] font-extrabold tracking-[.1em] uppercase">{{ t.nextUp }} · {{ t.sev[nextGroup.first.severity] }}</span>
              <span v-if="nextGroup.rest.length" class="ml-auto font-mono text-[12.5px] text-muted">{{ t.places(nextGroup.rest.length + 1) }}</span>
            </div>
            <div class="grid gap-4 p-5">
              <h2 class="text-[21px] leading-snug font-extrabold tracking-tight text-balance">{{ nextGroup.first.title.split(': ')[0] }}</h2>
              <p v-if="nextGroup.first.author" class="-mt-3 text-[12.5px] text-muted"><a :href="`https://github.com/${nextGroup.first.author}`" target="_blank" rel="noopener noreferrer" class="hover:text-accent hover:underline">{{ t.byAuthor(nextGroup.first.author) }}</a></p>
              <p class="max-w-[75ch] text-[15px] leading-relaxed text-muted">{{ nextGroup.first.explain }}</p>
              <div v-if="nextGroup.rest.length" class="flex flex-wrap gap-1.5">
                <span v-for="x in (nextOpen ? [nextGroup.first, ...nextGroup.rest] : [nextGroup.first, ...nextGroup.rest].slice(0, 2))" :key="x.key"
                  class="max-w-full truncate rounded-md bg-panel2 px-2 py-0.5 font-mono text-[12.5px] text-muted ring-1 ring-line">{{ placeOf(x) }}</span>
                <button class="rounded-md px-2 py-0.5 text-[12.5px] font-semibold text-accent hover:bg-accent-soft" @click="nextOpen = !nextOpen">{{ nextOpen ? t.showLess : t.morePlaces(nextGroup.rest.length - 1) }}</button>
              </div>
              <div class="grid gap-3 rounded-xl bg-panel2 px-4 py-3.5 ring-1 ring-line">
                <div class="caps">{{ t.howLabel }}</div>
                <PerPlace v-if="nextPP && nextPP.plan" :pp="nextPP" :t="t" />
                <div v-else-if="nextGroup.first.plan" class="grid gap-1.5"><CodeLine v-for="(c, k) in nextGroup.first.plan" :key="k" :code="c" :t="t" /></div>
                <template v-else>
                  <FixSteps :text="nextGroup.first.fix" :t="t" :hide="nextPP ? nextPP.hide : undefined" />
                  <PerPlace v-if="nextPP" class="border-t border-line pt-3" :pp="nextPP" :t="t" />
                </template>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                <button v-if="nextGroup.fixable.length" class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="askFix(nextGroup.fixable)">{{ t.fixNow }}</button>
                <button class="ml-auto rounded-lg px-2 py-2.5 text-[13px] text-muted hover:text-accent hover:underline" @click="feedbackAsk = { key: nextGroup.first.key }">{{ t.reportFp }}</button>
                <button class="rounded-xl px-3 py-2.5 text-[14px] font-semibold text-muted hover:text-fg" @click="askHide([nextGroup.first, ...nextGroup.rest])">{{ t.ignore }}…</button>
              </div>
            </div>
          </article>
          <h2 v-if="view === 'sev' && nextGroup && sections.length" class="px-5 pt-5 text-[13px] font-bold tracking-[.1em] text-muted uppercase">{{ t.remaining }} · {{ listGroups.length }}</h2>
          <section v-for="rs in (view === 'repo' ? repoSections : [])" :key="'r' + rs.repo">
            <h2 class="flex items-center gap-2 px-5 pt-4 pb-0.5">
              <span class="caps !text-fg" :class="rs.repo ? 'font-mono !normal-case !tracking-normal' : ''">{{ rs.repo || t.scope_machine }}</span>
              <span class="num text-[13px] font-bold text-muted">{{ rs.groups.length }}</span>
            </h2>
            <div class="grid gap-2 px-3 pt-2 pb-1">
              <FindingRow v-for="(g, i) in rs.groups" :key="rs.repo + g.first.rule_id" :group="g" :index="i" :t="t" :busy="busy" @fix="askFix" @ignore="askHide" @report="k => (feedbackAsk = { key: k })" />
            </div>
          </section>
          <section v-for="sec in (view === 'sev' ? sections : [])" :key="sec.sev">
            <h2 class="flex items-center gap-2 px-5 pt-4 pb-0.5">
              <span class="h-2.5 w-2.5 rounded-full" :class="{ critical: 'bg-rail-crit', high: 'bg-rail-high', medium: 'bg-rail-med', low: 'bg-rail-low', info: 'bg-rail-info' }[sec.sev]" />
              <span class="caps !text-fg">{{ t.sev[sec.sev] }}</span>
              <span class="num text-[13px] font-bold text-muted">{{ sec.groups.length }}</span>
            </h2>
            <div class="grid gap-2 px-3 pt-2 pb-1">
              <FindingRow v-for="(g, i) in sec.groups" :key="g.first.rule_id" :group="g" :index="i" :t="t" :busy="busy" @fix="askFix" @ignore="askHide" @report="k => (feedbackAsk = { key: k })" />
            </div>
          </section>
          <section v-if="hiddenGroups.length" class="mx-3 mt-4 mb-1 rounded-2xl bg-panel2/60 px-4 py-3.5 ring-1 ring-line">
            <div class="flex items-center gap-2">
              <h2 class="caps">{{ t.hiddenHere }} · <span class="num">{{ hiddenGroups.length }}</span></h2>
              <button class="ml-auto rounded-lg px-2 py-1 text-[13px] font-semibold text-accent hover:bg-panel" @click="restore(ignored.map(x => x.key))">{{ t.restoreAll }}</button>
            </div>
            <div v-for="g in hiddenGroups" :key="g.first.rule_id" class="mt-2 flex items-center gap-3 text-[14px]">
              <span class="h-2 w-2 shrink-0 rounded-full" :class="{ critical: 'bg-rail-crit', high: 'bg-rail-high', medium: 'bg-rail-med', low: 'bg-rail-low', info: 'bg-rail-info' }[g.first.severity]" />
              <span class="min-w-0 flex-1 truncate">{{ g.first.title.split(': ')[0] }}<span v-if="g.keys.length > 1" class="text-muted"> · {{ t.places(g.keys.length) }}</span></span>
              <span class="hidden shrink-0 text-[12.5px] text-muted sm:inline">{{ t.until(fmtDate(g.first.until)) }}</span>
              <button class="shrink-0 rounded-lg border border-line bg-panel px-2.5 py-1 text-[13px] font-semibold hover:text-accent" @click="restore(g.keys)">{{ t.restore }}</button>
            </div>
          </section>
          <div v-if="data" class="mx-3 mt-4 mb-1 flex flex-wrap items-center gap-x-3 gap-y-1 px-2 text-[13px] text-muted">
            <span>{{ t.suggestCheckHelp }}</span>
            <button class="font-semibold text-accent hover:underline" @click="feedbackAsk = { key: '' }">{{ t.suggestCheck }}</button>
          </div>
          <section v-if="data && cat !== 'all' && catPassed.length" class="px-5 pt-5 pb-4">
            <h2 class="caps mb-3">{{ t.safeView }} · <span class="num">{{ catPassed.length }}</span></h2>
            <ul v-if="catPassed.length" class="grid gap-x-6 gap-y-2 sm:grid-cols-2">
              <li v-for="p in catPassed" :key="p.rule_id" class="flex items-start gap-2.5 text-[14.5px]">
                <span class="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-ok-bg text-[12px] font-bold text-ok">✓</span>
                <span>{{ p.label }}<TierBadge v-if="p.tier" class="ml-2 align-[2px]" :tier="p.tier" :t="t" /></span>
              </li>
            </ul>
          </section>
        </div>
        <p class="border-t border-line px-5 py-3 text-[13px] text-muted">{{ t.local }}</p>
      </main>
    </div>
    </template>

    <!-- first sign-in: offer a passkey -->
    <div v-if="onboarding" class="fixed inset-0 z-40 grid place-items-center bg-page/90 p-4 backdrop-blur-md">
      <section class="panel rise grid w-full max-w-md gap-4 p-7 text-center shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="onb-title">
        <div class="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-accent-soft text-accent">
          <svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="4" fill="none" stroke="currentColor" stroke-width="2" /><path d="M2 21c0-3.9 3.1-7 7-7 1.5 0 2.9.5 4 1.3M17 11a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm0 6v5m0-2h2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
        </div>
        <h2 id="onb-title" class="text-[20px] font-bold">{{ t.onbTitle }}</h2>
        <p class="text-[15px] text-muted">{{ t.onbText }}</p>
        <div class="grid gap-2 pt-1">
          <button class="rounded-xl bg-accent px-4 py-3 text-[15px] font-semibold text-accent-ink hover:brightness-110" @click="onbAdd">{{ onbFailed ? t.onbRetry : t.onbAdd }}</button>
        </div>
        <p class="text-[12.5px] text-muted">{{ t.onbSafe }}</p>
      </section>
    </div>

    <!-- scan in progress: a modal over a blurred page -->
    <Transition enter-from-class="opacity-0" leave-to-class="opacity-0" enter-active-class="transition-opacity duration-200" leave-active-class="transition-opacity duration-300">
      <div v-if="prog" class="fixed inset-0 z-50 grid place-items-center bg-page/60 p-4 backdrop-blur-md" role="dialog" aria-modal="true" aria-live="polite" :aria-label="t.scanning">
        <section class="panel rise grid w-full max-w-md justify-items-center gap-4 p-7 text-center shadow-2xl">
          <svg width="112" height="112" viewBox="0 0 112 112" aria-hidden="true">
            <circle cx="56" cy="56" r="46" fill="none" stroke="var(--color-line)" stroke-width="9" />
            <circle cx="56" cy="56" r="46" fill="none" stroke="var(--color-accent)" stroke-width="9" stroke-linecap="round"
              :stroke-dasharray="`${(2 * Math.PI * 46 * progPct) / 100} ${2 * Math.PI * 46}`" transform="rotate(-90 56 56)" class="transition-all duration-300" />
            <text x="56" y="63" text-anchor="middle" font-size="24" font-weight="800" fill="var(--color-fg)" font-family="Plus Jakarta Sans, sans-serif">{{ progPct }}%</text>
          </svg>
          <h2 class="text-[19px] font-bold">{{ t.scanning }}</h2>
          <div class="grid w-full gap-1.5 text-[14px]">
            <div v-if="prog.pending.length" class="flex items-center justify-center gap-2 font-semibold">
              <svg class="animate-spin text-accent" width="15" height="15" viewBox="0 0 16 16" aria-hidden="true"><path d="M13.5 8A5.5 5.5 0 1 1 8 2.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
              <span>{{ t.checkingNames }}: {{ prog.pending[0] }}</span>
            </div>
            <div v-if="prog.done.length" :key="prog.done.length" class="rise flex items-center justify-center gap-2 text-ok">
              <span>✓</span><span>{{ prog.done[prog.done.length - 1].label }}</span>
            </div>
          </div>
        </section>
      </div>
    </Transition>

    <FeedbackDialog v-if="feedbackAsk" :t="t" :finding-key="feedbackAsk.key" :bug="!!feedbackAsk.bug" @close="feedbackAsk = null" />

    <!-- hide confirmation -->
    <div v-if="hideAsk" class="fixed inset-0 z-20 grid place-items-center bg-black/55 p-4 backdrop-blur-sm" @click.self="hideAsk = null">
      <section class="panel rise grid w-full max-w-md gap-4 p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="hide-title">
        <h2 id="hide-title" class="text-[18px] font-bold">{{ t.hideTitle }}</h2>
        <p class="rounded-xl bg-panel2 px-4 py-3 text-[14.5px] font-semibold ring-1 ring-line">{{ hideAsk.list[0].title.split(': ')[0] }}<span v-if="hideAsk.list.length > 1" class="font-normal text-muted"> · {{ t.places(hideAsk.list.length) }}</span></p>
        <div class="grid gap-2">
          <span class="caps">{{ t.hideFor }}</span>
          <div class="grid grid-cols-3 gap-1.5">
            <button v-for="d in [1, 7, 30]" :key="d" class="rounded-lg px-2 py-2 text-[13.5px] font-semibold ring-1"
              :class="hideAsk.days === d ? 'bg-accent text-accent-ink ring-accent' : 'bg-panel2 ring-line hover:text-accent'"
              @click="hideAsk.days = d">{{ t.ignoreFor(d) }}</button>
          </div>
        </div>
        <ul class="grid gap-1.5 text-[14px] leading-snug">
          <li>• {{ t.hideBack(hideUntil) }}</li>
          <li>• {{ t.hideScore }}</li>
          <li>• {{ t.hideWhere }}</li>
        </ul>
        <div class="flex justify-end gap-2">
          <button class="rounded-xl px-4 py-2.5 text-[14px] font-semibold text-muted hover:text-fg" @click="hideAsk = null">{{ t.cancel }}</button>
          <button class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110" @click="confirmHide">{{ t.hideConfirm }}</button>
        </div>
      </section>
    </div>

    <!-- fix confirmation -->
    <div v-if="sheet" class="fixed inset-0 z-20 grid place-items-center bg-black/55 p-4 backdrop-blur-sm" @click.self="sheet = null">
      <section class="panel rise grid max-h-[85vh] w-full max-w-lg gap-3 overflow-y-auto p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="sheet-title">
        <h2 id="sheet-title" class="text-[18px] font-bold">{{ t.sheetTitle(sheetOn) }}</h2>
        <label v-for="x in sheet" :key="x.f.key" class="grid grid-cols-[18px_1fr] gap-3 border-t border-line pt-3">
          <input v-model="x.on" type="checkbox" class="mt-1 h-4 w-4 accent-[var(--color-accent)]" />
          <span class="min-w-0">
            <span class="block text-[15px] font-semibold break-words">{{ x.f.title }}</span>
            <span class="mt-0.5 block font-mono text-[12.5px] text-muted break-all">$ {{ (x.f.plan || []).join(' && ') }}</span>
            <span class="block text-[12.5px]" :class="x.f.undoable ? 'text-ok' : 'text-med'">{{ x.f.undoable ? t.undoable : t.noUndo }}</span>
          </span>
        </label>
        <div class="flex justify-end gap-2 pt-2">
          <button class="rounded-xl border border-line px-4 py-2 text-[14px] font-semibold hover:bg-panel2" @click="sheet = null">{{ t.cancel }}</button>
          <button class="rounded-xl bg-accent px-4 py-2 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="!sheetOn" @click="applyFix">{{ t.apply(sheetOn) }}</button>
        </div>
      </section>
    </div>

    <div v-if="toast" class="rise fixed right-4 bottom-4 left-4 z-30 mx-auto flex max-w-md items-start gap-3 rounded-xl px-4 py-3 text-[14px] shadow-2xl sm:left-auto"
      :class="toastErr ? 'bg-crit text-white' : 'bg-fg text-page'" :role="toastErr ? 'alert' : 'status'">
      <span class="flex-1 break-words">{{ toast }}</span>
      <button v-if="toastAction" class="-my-0.5 shrink-0 rounded-lg bg-page/15 px-2.5 py-0.5 font-semibold hover:bg-page/25" @click="toastAction.run(); toast = ''; toastAction = null">{{ toastAction.label }}</button>
      <button class="-mr-1 rounded px-1.5 font-bold opacity-80 hover:opacity-100" :aria-label="t.close" @click="toast = ''">✕</button>
    </div>
  </div>
</template>
