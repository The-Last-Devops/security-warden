<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api } from './api.js'
import { dict } from './i18n.js'
import { passkeySupported } from './passkey.js'
import SevChip from './components/SevChip.vue'
import Segmented from './components/Segmented.vue'
import FindingRow from './components/FindingRow.vue'

// Per-viewer preferences: "auto" follows the browser / system.
const pref = key => { try { return localStorage.getItem(key) } catch { return null } }
const save = (key, v) => { try { localStorage.setItem(key, v) } catch {} }
const langPref = ref(pref('sw.lang') || 'auto')
const themePref = ref(pref('sw.theme') || 'auto')
const browserLang = () => ((navigator.languages || [navigator.language || 'en']).find(l => /^(vi|en)/i.test(l)) || 'en').slice(0, 2).toLowerCase()
const lang = computed(() => (langPref.value === 'auto' ? browserLang() : langPref.value))
const t = computed(() => dict[lang.value] || dict.en)
function applyTheme(v) { const r = document.documentElement; if (v === 'auto') delete r.dataset.theme; else r.dataset.theme = v }
applyTheme(themePref.value)
document.documentElement.lang = lang.value
watch(themePref, v => { save('sw.theme', v); applyTheme(v) })
watch(langPref, v => save('sw.lang', v))
watch(lang, l => { document.documentElement.lang = l; if (meta.value) load() })

const meta = ref(null)
const data = ref(null)
const busy = ref(false)
const signedOut = ref(false)
const cat = ref('all')
const sheet = ref(null)
const toast = ref('')
const toastErr = ref(false)
function say(msg, isError = false) {
  toast.value = msg; toastErr.value = isError
  if (!isError) setTimeout(() => { if (toast.value === msg) toast.value = '' }, 5000)
}
const fail = e => { if (e.status === 401) signedOut.value = true; else say(`${t.value.error}: ${e.message}`, true) }

const categories = ['secrets', 'exposure', 'settings', 'persistence', 'ai', 'devtools', 'software']
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
  const before = new Set(findings.value.map(f => f.key))
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
      if (!p.running && p.done.length >= p.total && elapsed >= MIN_MS) break
    }
    data.value = await api.scan(lang.value)
    const after = new Set(findings.value.map(f => f.key))
    let added = 0, gone = 0
    for (const k of after) if (!before.has(k)) added++
    for (const k of before) if (!after.has(k)) gone++
    if (!first) say(t.value.scanDone(after.size, added, gone))
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
const sources = computed(() => data.value?.sources || [])
const passedList = computed(() => data.value?.passed || [])
const passedByCat = computed(() => {
  const by = {}
  for (const p of passedList.value) (by[p.category] ||= []).push(p)
  return categories.filter(c => by[c]).map(c => ({ cat: c, items: by[c] }))
})
const counts = computed(() => { const c = {}; for (const f of findings.value) c[f.category] = (c[f.category] || 0) + 1; return c })
const sevCounts = computed(() => { const c = {}; for (const f of findings.value) c[f.severity] = (c[f.severity] || 0) + 1; return c })
const worst = computed(() => {
  const w = {}
  for (const f of findings.value) if (w[f.category] === undefined || sevOrder.indexOf(f.severity) < sevOrder.indexOf(w[f.category])) w[f.category] = f.severity
  return w
})
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
const listGroups = computed(() => (nextGroup.value ? groups.value.slice(1) : groups.value))
const sections = computed(() => sevOrder.map(sev => ({ sev, groups: listGroups.value.filter(g => g.first.severity === sev) })).filter(x => x.groups.length))
const nextOpen = ref(false)
const scoreColor = computed(() => { const sc = data.value?.scan.score ?? 0; return sc >= 75 ? 'var(--color-ok)' : sc >= 50 ? 'var(--color-med)' : 'var(--color-crit)' })
const RING = 2 * Math.PI * 30
const safeFixes = computed(() => findings.value.filter(f => f.can_fix))
// Points earned by fixing every safe item (each rule counts once).
const safeGain = computed(() => { const seen = {}; for (const f of safeFixes.value) seen[f.rule_id] = f.gain || 0; return Object.values(seen).reduce((a, b) => a + b, 0) })
const passedN = computed(() => (data.value?.scan.passed || []).length)
const window = globalThis.window
const fmtTime = iso => (iso ? new Date(iso).toLocaleTimeString(lang.value, { hour: '2-digit', minute: '2-digit' }) : '')
const fmtDate = iso => new Date(iso).toLocaleDateString(lang.value, { day: 'numeric', month: 'short', year: 'numeric' })
const listTitle = computed(() => (cat.value === 'all' ? t.value.issuesTitle : cat.value === 'checked' ? t.value.checkedTitle : cat.value === 'ignored' ? t.value.ignoredTitle : cat.value === 'safe' ? t.value.safeTitle : t.value[cat.value]))

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
async function ignoreFindings(list, days) {
  try { const r = await api.ignore(list.map(f => f.key), days); say(t.value.ignoredDone(r.ignored)); await load() } catch (e) { fail(e) }
}
async function restore(keys) { try { await api.unignore(keys); say(t.value.restored); await load() } catch (e) { fail(e) } }
async function logout() { try { await api.logout() } catch {} ; signedOut.value = true }
const menuOpen = ref(false)
const upd = ref(null)
async function refreshUpdate() { try { upd.value = await api.updateStatus() } catch {} }
async function toggleAuto() {
  if (!upd.value) return
  try { const r = await api.setAutoUpdate(!upd.value.auto); upd.value.auto = r.auto } catch (e) { fail(e) }
}
onMounted(refreshUpdate)
function onKey(e) { if (e.key === 'Escape') { sheet.value = null; menuOpen.value = false } }
onMounted(() => document.addEventListener('click', () => { menuOpen.value = false }))
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
      <p v-else-if="pk.count && !pk.available" class="text-[14px] text-muted">{{ t.passkeyNeedsLocalhost }} <a class="font-mono text-accent underline" :href="pk.localhost">{{ pk.localhost }}</a></p>
      <p class="text-[14px] text-muted">{{ pk.count ? t.signInHelp : t.signedOut }}</p>
    </section>
  </div>

  <div v-else class="min-h-screen" @keydown="onKey">
    <!-- top bar -->
    <header class="border-b border-line">
      <div class="mx-auto flex max-w-[1280px] flex-wrap items-center gap-x-4 gap-y-3 px-4 py-3.5 sm:px-6">
        <button class="flex items-center gap-2.5 rounded-lg text-[15px] font-extrabold tracking-[.06em] uppercase hover:text-accent" :title="t.home" @click="cat = 'all'; window.scrollTo({ top: 0, behavior: 'smooth' })">
          <svg width="20" height="22" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" fill="var(--color-accent)" /></svg>
          Security Warden
        </button>
        <span class="hidden items-center gap-2 text-[13px] text-muted lg:flex">
          <i class="h-2 w-2 rounded-full bg-ok shadow-[0_0_0_4px_var(--color-ok-bg)]" />
          {{ t.watching }} · {{ data?.scan.host || '' }} · {{ t.lastScan(fmtTime(data?.scanned_at)) }}
        </span>
        <div class="relative ml-auto">
          <button class="grid h-10 w-10 place-items-center rounded-xl border border-line bg-panel2 text-muted hover:text-fg" :aria-label="t.settings" :aria-expanded="menuOpen" @click.stop="menuOpen = !menuOpen">
            <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Z" fill="none" stroke="currentColor" stroke-width="2" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" fill="none" stroke="currentColor" stroke-width="1.6" /></svg>
          </button>
          <div v-if="menuOpen" class="rise absolute right-0 z-30 mt-2 grid w-72 gap-4 rounded-2xl border border-line bg-panel p-4 shadow-2xl" role="menu" @click.stop>
            <div class="grid gap-2"><span class="caps">{{ t.theme }}</span><Segmented v-model="themePref" :options="themeOptions" :label="t.theme" /></div>
            <div class="grid gap-2"><span class="caps">{{ t.language }}</span><Segmented v-model="langPref" :options="langOptions" :label="t.language" /></div>
            <div v-if="canPasskey || pk.count" class="grid gap-2">
              <span class="caps">{{ t.passkeysSection }} · <span class="num">{{ pk.count }}</span></span>
              <div class="flex gap-2">
                <button v-if="canPasskey" class="flex-1 rounded-[10px] bg-accent px-3 py-2 text-[13px] font-semibold text-accent-ink hover:brightness-110" @click="menuOpen = false; addPasskey()">{{ t.addPasskey }}</button>
                <button v-if="pk.count" class="rounded-[10px] border border-line px-3 py-2 text-[13px] font-semibold text-muted hover:text-crit" @click="menuOpen = false; clearPasskeys()">{{ t.removePasskeys }}</button>
              </div>
            </div>
            <div v-if="upd" class="grid gap-2">
              <span class="caps">{{ t.updates }}</span>
              <label class="flex items-center justify-between gap-3 text-[14px]">
                <span>{{ t.autoUpdate }}</span>
                <button type="button" role="switch" :aria-checked="upd.auto" class="relative h-6 w-11 rounded-full transition-colors" :class="upd.auto ? 'bg-accent' : 'bg-line'" @click="toggleAuto">
                  <span class="absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all" :class="upd.auto ? 'left-[22px]' : 'left-0.5'" />
                </button>
              </label>
              <span class="text-[12.5px] text-muted">{{ t.version(upd.current) }}</span>
            </div>
            <div class="border-t border-line pt-3">
              <button class="w-full rounded-[10px] px-3 py-2 text-left text-[14px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="menuOpen = false; logout()">{{ t.signOut }}</button>
            </div>
          </div>
        </div>
      </div>
    </header>

    <div v-if="upd && upd.available" class="mx-auto mt-4 flex max-w-[1280px] flex-wrap items-center gap-x-3 gap-y-1 px-4 sm:px-6">
      <div class="flex w-full flex-wrap items-center gap-x-3 gap-y-1 rounded-xl bg-accent-soft px-4 py-2.5 text-[14px] ring-1 ring-accent/30">
        <span class="font-semibold text-accent">{{ t.newVersion(upd.latest) }}</span>
        <span class="text-muted">{{ upd.method === 'brew' ? t.updateHowBrew : t.updateHowManual }}</span>
      </div>
    </div>
    <div class="mx-auto grid max-w-[1280px] gap-5 px-4 py-5 sm:px-6 lg:grid-cols-[290px_1fr]">
      <!-- left: score, counts, groups -->
      <aside class="grid content-start gap-5">
        <section class="panel grid gap-4 p-5">
          <div class="flex items-center gap-4">
            <svg width="76" height="76" viewBox="0 0 76 76" role="img" :aria-label="`${t.score}: ${data?.scan.score ?? 0}/100`">
              <circle cx="38" cy="38" r="30" fill="none" stroke="var(--color-line)" stroke-width="7" />
              <circle cx="38" cy="38" r="30" fill="none" :stroke="scoreColor" stroke-width="7" stroke-linecap="round"
                :stroke-dasharray="`${(RING * Math.max(data?.scan.score ?? 0, 1)) / 100} ${RING}`" transform="rotate(-90 38 38)" class="transition-all duration-700" />
              <text x="38" y="44" text-anchor="middle" font-size="21" font-weight="800" :fill="scoreColor" font-family="Plus Jakarta Sans, sans-serif">{{ data?.scan.score ?? 0 }}</text>
            </svg>
            <div class="min-w-0">
              <div class="caps">{{ t.score }}</div>
              <p class="mt-0.5 text-[15px] leading-snug font-semibold">{{ data ? (sevCounts.critical ? t.verdictCrit : t.verdict(data.scan.score)) : t.scanning }}</p>
            </div>
          </div>
          <div>
            <div class="flex justify-between text-[13px] text-muted"><span>{{ t.passedOf(passedN, data?.scan.checked || 0) }}</span><span class="num">{{ data?.scan.checked ? Math.round((passedN / data.scan.checked) * 100) : 0 }}%</span></div>
            <div class="mt-1.5 h-1.5 overflow-hidden rounded-full bg-line"><div class="h-full rounded-full bg-ok transition-[width] duration-700" :style="{ width: (data?.scan.checked ? (passedN / data.scan.checked) * 100 : 0) + '%' }" /></div>
          </div>
          <button v-if="safeFixes.length" class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="askFix(safeFixes)">{{ safeGain ? t.fixGain(safeFixes.length, safeGain) : t.fixSafe(safeFixes.length) }}</button>
          <div class="grid grid-cols-2 gap-2">
            <button class="inline-flex items-center justify-center gap-2 rounded-xl border border-line bg-panel2 px-3 py-2 text-[13.5px] font-semibold hover:text-accent disabled:opacity-50" :disabled="busy" @click="load(true)">
              <svg :class="busy ? 'animate-spin' : ''" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M13.5 8A5.5 5.5 0 1 1 8 2.5c1.6 0 3 .7 4 1.7M12.5 1.5v3h-3" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" /></svg>
              {{ busy ? t.scanning : t.rescan }}
            </button>
            <button class="rounded-xl border border-line bg-panel2 px-3 py-2 text-[13.5px] font-semibold hover:text-accent disabled:opacity-50" :disabled="busy" @click="undo">{{ t.undoShort }}</button>
          </div>
        </section>

        <nav class="panel p-2" :aria-label="t.groups">
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px] font-semibold"
            :class="cat === 'all' ? 'bg-accent-soft text-accent' : 'hover:bg-panel2'" @click="cat = 'all'">
            {{ t.all }} <span class="num">{{ findings.length }}</span>
          </button>
          <button v-for="c in categories" :key="c" class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px]"
            :class="cat === c ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = c">
            {{ t[c] }}
            <span class="num font-bold" :class="counts[c] ? worstText[worst[c]] : 'text-muted/50'">{{ counts[c] || 0 }}</span>
          </button>
          <div class="my-1.5 border-t border-line" />
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px]"
            :class="cat === 'safe' ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = 'safe'">
            <span class="flex items-center gap-2"><span class="text-ok">✓</span>{{ t.safeView }}</span> <span class="num font-bold text-ok">{{ passedList.length }}</span>
          </button>
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px]"
            :class="cat === 'checked' ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = 'checked'">
            {{ t.checkedView }} <span class="num text-muted">{{ sources.length }}</span>
          </button>
          <button class="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-left text-[15px]"
            :class="cat === 'ignored' ? 'bg-accent-soft font-semibold text-accent' : 'text-fg/85 hover:bg-panel2'" @click="cat = 'ignored'">
            {{ t.ignoredView }} <span class="num text-muted">{{ ignored.length }}</span>
          </button>
        </nav>
      </aside>

      <!-- right: list -->
      <main class="panel min-w-0 self-start">
        <div class="flex flex-wrap items-center gap-3 border-b border-line px-5 py-4">
          <h1 class="text-[19px] font-bold">{{ listTitle }}</h1>
          <span v-if="!['checked', 'ignored', 'safe'].includes(cat)" class="num rounded-full bg-panel2 px-2.5 py-0.5 text-[13px] font-bold text-muted ring-1 ring-line">{{ groups.length }}</span>
          <span v-if="ignored.length && cat !== 'ignored'" class="ml-auto text-[13px] text-muted">{{ t.ignoredNote(ignored.length) }}</span>
        </div>

        <!-- checked -->
        <div v-if="cat === 'checked'">
          <div v-for="(s, i) in sources" :key="s.name" class="rise grid grid-cols-[1fr_auto] items-center gap-x-4 border-t border-line px-5 py-3 first:border-t-0 sm:grid-cols-[minmax(0,1fr)_8rem_auto]" :style="{ animationDelay: `${Math.min(i, 20) * 18}ms` }">
            <div class="min-w-0"><div class="text-[15px] font-semibold">{{ s.label }}</div><div class="text-[13px] text-muted">{{ t[s.category] || '' }}<span v-if="s.detail"> · {{ s.detail }}</span></div></div>
            <div class="num hidden text-right text-[13px] text-muted sm:block">{{ s.state === 'skipped' ? '—' : t.items(s.items) }}</div>
            <span class="rounded-full px-2.5 py-1 text-[11.5px] leading-none font-bold tracking-[.06em] uppercase" :class="stCls[s.state]">
              {{ s.state === 'ok' ? t.stOk : s.state === 'issues' ? t.stIssues(s.issues) : s.state === 'skipped' ? t.stSkipped : t.stError }}
            </span>
          </div>
        </div>

        <!-- safe: what already passes -->
        <div v-else-if="cat === 'safe'">
          <p class="border-b border-line bg-ok-bg px-5 py-3 text-[14.5px] font-semibold text-ok">{{ t.safeNote(passedList.length) }}</p>
          <section v-for="g in passedByCat" :key="g.cat" class="border-b border-line px-5 py-4 last:border-b-0">
            <h2 class="caps mb-2.5">{{ t[g.cat] }} · <span class="num">{{ g.items.length }}</span></h2>
            <ul class="grid gap-x-6 gap-y-2 sm:grid-cols-2">
              <li v-for="p in g.items" :key="p.rule_id" class="flex items-start gap-2.5 text-[14.5px]">
                <span class="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-ok-bg text-[12px] font-bold text-ok">✓</span>
                <span>{{ p.label }}</span>
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
          <p v-if="data && !groups.length && cat !== 'all'" class="px-5 py-10 text-center text-muted">{{ t.noIssues }}</p>
          <p v-if="data && !groups.length && cat === 'all'" class="mx-5 my-6 rounded-xl bg-ok-bg px-5 py-4 text-center text-[15px] font-semibold text-ok">{{ t.allClear }}</p>
          <article v-if="nextGroup" class="m-3 mb-1 overflow-hidden rounded-2xl bg-panel2 ring-1 ring-line">
            <div class="flex flex-wrap items-center gap-2 px-5 py-2.5"
              :class="{ critical: 'bg-rail-crit text-white', high: 'bg-rail-high text-white', medium: 'bg-rail-med text-[#1a1300]', low: 'bg-rail-low text-white', info: 'bg-rail-info text-white' }[nextGroup.first.severity]">
              <span class="text-[12.5px] font-extrabold tracking-[.1em] uppercase">{{ t.nextUp }} · {{ t.sev[nextGroup.first.severity] }}</span>
              <span v-if="nextGroup.first.gain" class="num ml-auto rounded-full bg-black/15 px-2.5 py-0.5 text-[13px] font-bold">{{ t.gain(nextGroup.first.gain) }}</span>
            </div>
            <div class="grid gap-3 p-5">
            <h2 class="text-[21px] leading-snug font-extrabold tracking-tight">{{ nextGroup.first.title.split(': ')[0] }}</h2>
            <p class="max-w-[72ch] text-[15px] leading-relaxed text-fg/85">{{ nextGroup.first.explain }}</p>
            <div class="rounded-xl bg-panel px-4 py-3 ring-1 ring-line">
              <div class="caps mb-1">{{ t.howLabel }}</div>
              <div v-if="nextGroup.first.plan" class="font-mono text-[13.5px]">{{ nextGroup.first.plan.map(p => '$ ' + p).join('\n') }}</div>
              <p v-else class="text-[14.5px] leading-relaxed">{{ nextGroup.first.fix }}</p>
            </div>
            <ul v-if="nextOpen" class="grid max-h-60 gap-1 overflow-y-auto rounded-xl bg-panel px-4 py-3 font-mono text-[12.5px] text-muted ring-1 ring-line">
              <li v-for="x in [nextGroup.first, ...nextGroup.rest]" :key="x.key" class="break-all">{{ x.title.includes(': ') ? x.title.slice(x.title.indexOf(': ') + 2) : x.title }}</li>
            </ul>
            <div class="flex flex-wrap items-center gap-2">
              <button v-if="nextGroup.fixable.length" class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="askFix(nextGroup.fixable)">{{ t.fixNow }}</button>
              <button v-if="nextGroup.rest.length" class="rounded-xl border border-line bg-panel px-4 py-2.5 text-[14px] font-semibold hover:text-accent" @click="nextOpen = !nextOpen">{{ nextOpen ? t.showLess : t.seePlaces(nextGroup.rest.length + 1) }}</button>
              <button class="ml-auto rounded-xl px-3 py-2.5 text-[14px] font-semibold text-muted hover:text-fg" @click="ignoreFindings([nextGroup.first, ...nextGroup.rest], 7)">{{ t.later }}</button>
            </div>
            </div>
          </article>
          <h2 v-if="nextGroup && sections.length" class="px-5 pt-5 text-[13px] font-bold tracking-[.1em] text-muted uppercase">{{ t.remaining }} · {{ listGroups.length }}</h2>
          <section v-for="sec in sections" :key="sec.sev">
            <h2 class="flex items-center gap-2 px-5 pt-4 pb-0.5">
              <span class="h-2.5 w-2.5 rounded-full" :class="{ critical: 'bg-rail-crit', high: 'bg-rail-high', medium: 'bg-rail-med', low: 'bg-rail-low', info: 'bg-rail-info' }[sec.sev]" />
              <span class="caps !text-fg">{{ t.sev[sec.sev] }}</span>
              <span class="num text-[13px] font-bold text-muted">{{ sec.groups.length }}</span>
            </h2>
            <div class="grid gap-2 px-3 pt-2 pb-1">
              <FindingRow v-for="(g, i) in sec.groups" :key="g.first.rule_id" :group="g" :index="i" :t="t" :busy="busy" @fix="askFix" @ignore="ignoreFindings" />
            </div>
          </section>
        </div>
        <p class="border-t border-line px-5 py-3 text-[13px] text-muted">{{ t.local }}</p>
      </main>
    </div>

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
          <div>
            <h2 class="text-[19px] font-bold">{{ t.scanning }}</h2>
            <p class="mt-0.5 text-[14px] text-muted">{{ t.scanningNow(prog.done.length, prog.total || '…') }}</p>
          </div>
          <div class="h-1.5 w-full overflow-hidden rounded-full bg-line"><div class="h-full rounded-full bg-accent transition-[width] duration-300" :style="{ width: progPct + '%' }" /></div>
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
      <button class="-mr-1 rounded px-1.5 font-bold opacity-80 hover:opacity-100" :aria-label="t.close" @click="toast = ''">✕</button>
    </div>
  </div>
</template>
