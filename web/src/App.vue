<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api } from './api.js'
import { dict } from './i18n.js'
import Gauge from './components/Gauge.vue'
import SevChip from './components/SevChip.vue'
import Segmented from './components/Segmented.vue'
import FindingCard from './components/FindingCard.vue'
import { passkeySupported } from './passkey.js'

// Per-viewer preferences: "auto" follows the browser / system.
const pref = key => { try { return localStorage.getItem(key) } catch { return null } }
const save = (key, v) => { try { localStorage.setItem(key, v) } catch {} }
const langPref = ref(pref('sw.lang') || 'auto')
const themePref = ref(pref('sw.theme') || 'auto')
const browserLang = () => ((navigator.languages || [navigator.language || 'en']).find(l => /^(vi|en)/i.test(l)) || 'en').slice(0, 2).toLowerCase()
const lang = computed(() => (langPref.value === 'auto' ? browserLang() : langPref.value))
const t = computed(() => dict[lang.value] || dict.en)

function applyTheme(v) {
  const root = document.documentElement
  if (v === 'auto') delete root.dataset.theme
  else root.dataset.theme = v
}
applyTheme(themePref.value)
watch(themePref, v => { save('sw.theme', v); applyTheme(v) })
watch(langPref, v => save('sw.lang', v))
watch(lang, l => { document.documentElement.lang = l; if (meta.value) load() }, { immediate: false })
document.documentElement.lang = lang.value

const meta = ref(null)
const data = ref(null)
const busy = ref(false)
const toast = ref('')
const signedOut = ref(false)
const cat = ref('all')
const sheet = ref(null)
const pk = ref({ count: 0, available: false, localhost: '' })
const canPasskey = computed(() => pk.value.available && passkeySupported())
async function refreshPasskey() { try { pk.value = await api.passkeyStatus() } catch {} }
async function signInPasskey() {
  busy.value = true
  try { await api.loginPasskey(); signedOut.value = false; meta.value = await api.meta(); load() }
  catch (e) { if (e.name !== 'NotAllowedError') say(`${t.value.error}: ${e.message}`) }
  finally { busy.value = false }
}
async function addPasskey() {
  try { const r = await api.addPasskey(); pk.value.count = r.count; say(t.value.passkeyAdded) }
  catch (e) { if (e.name !== 'NotAllowedError') say(`${t.value.error}: ${e.message}`) }
}
async function clearPasskeys() {
  try { await api.clearPasskeys(); pk.value.count = 0; say(t.value.passkeysRemoved) } catch (e) { say(`${t.value.error}: ${e.message}`) }
}

const categories = ['secrets', 'exposure', 'settings', 'persistence', 'ai', 'devtools', 'software']
const sevOrder = ['critical', 'high', 'medium', 'low', 'info']

function say(msg) { toast.value = msg; setTimeout(() => { if (toast.value === msg) toast.value = '' }, 4500) }

async function load(force = false) {
  busy.value = true
  try {
    data.value = await (force ? api.rescan(lang.value) : api.scan(lang.value))
  } catch (e) {
    if (e.status === 401) signedOut.value = true
    else say(`${t.value.error}: ${e.message}`)
  } finally { busy.value = false }
}

onMounted(async () => {
  refreshPasskey()
  try { meta.value = await api.meta() } catch (e) { if (e.status === 401) { signedOut.value = true; return } }
  load()
})
const sources = computed(() => data.value?.sources || [])
const stCls = { ok: 'bg-ok-bg text-ok', issues: 'bg-high-bg text-high', skipped: 'bg-info-bg text-info', error: 'bg-crit-bg text-crit' }

const findings = computed(() => data.value?.findings || [])
const counts = computed(() => {
  const c = {}
  for (const f of findings.value) c[f.category] = (c[f.category] || 0) + 1
  return c
})
const sevCounts = computed(() => {
  const c = {}
  for (const f of findings.value) c[f.severity] = (c[f.severity] || 0) + 1
  return c
})
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
const safeFixes = computed(() => findings.value.filter(f => f.can_fix))
const scannedAt = computed(() => data.value?.scanned_at ? new Date(data.value.scanned_at).toLocaleTimeString(lang.value, { hour: '2-digit', minute: '2-digit' }) : '')
const passedN = computed(() => (data.value?.scan.passed || []).length)

const themeOptions = computed(() => [
  { value: 'auto', label: t.value.auto }, { value: 'light', label: t.value.light }, { value: 'dark', label: t.value.dark },
])
const langOptions = computed(() => [{ value: 'auto', label: t.value.auto }, { value: 'en', label: 'EN' }, { value: 'vi', label: 'VI' }])

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
    say(bad.length ? `${t.value.done(ok)} ${t.value.failed}: ${bad[0].error}` : t.value.done(ok))
    await load(true)
  } catch (e) { say(`${t.value.error}: ${e.message}`) } finally { busy.value = false }
}
async function undo() {
  try {
    const r = await api.undo()
    say(r.error ? `${t.value.failed}: ${r.error}` : r.undone ? t.value.undone(r.undone) : t.value.nothingUndo)
    if (r.undone) await load(true)
  } catch (e) { say(`${t.value.error}: ${e.message}`) }
}
async function logout() { try { await api.logout() } catch {} ; signedOut.value = true }
function onKey(e) { if (e.key === 'Escape') sheet.value = null }
</script>

<template>
  <div v-if="signedOut" class="mx-auto mt-[16vh] max-w-md px-4">
    <section class="rise grid gap-4 rounded-2xl border border-line bg-panel p-7 text-center shadow-sm">
      <svg class="mx-auto" width="38" height="42" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" class="fill-accent" /><path d="m6.5 11 2.4 2.4L13.8 8.5" fill="none" stroke="var(--color-accent-ink)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
      <h1 class="font-display text-2xl font-bold tracking-tight">Security Warden</h1>
      <button v-if="canPasskey && pk.count" class="mx-auto inline-flex items-center gap-2 rounded-xl bg-accent px-5 py-2.5 text-sm font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="signInPasskey">
        <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="4" fill="none" stroke="currentColor" stroke-width="2"/><path d="M2 21c0-3.9 3.1-7 7-7 1.5 0 2.9.5 4 1.3M17 11a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm0 6v5m0-2h2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        {{ t.signInPasskey }}
      </button>
      <p v-else-if="pk.count && !pk.available" class="text-[13.5px] text-muted">{{ t.passkeyNeedsLocalhost }} <a class="font-mono text-accent underline" :href="pk.localhost">{{ pk.localhost }}</a></p>
      <p class="text-[13.5px] text-muted">{{ pk.count ? t.signInHelp : t.signedOut }}</p>
    </section>
  </div>

  <div v-else class="mx-auto max-w-[1200px] px-4 pt-5 pb-10 sm:px-6 sm:pt-7" @keydown="onKey">
    <!-- top bar -->
    <header class="mb-5 flex flex-wrap items-center gap-x-4 gap-y-3">
      <div class="flex items-center gap-2.5">
        <svg width="22" height="24" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" class="fill-accent" /><path d="m6.5 11 2.4 2.4L13.8 8.5" fill="none" stroke="var(--color-accent-ink)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
        <span class="font-display text-[19px] font-bold tracking-tight">Security Warden</span>
        <span class="num rounded bg-panel px-1.5 py-0.5 text-[10.5px] text-muted ring-1 ring-line">{{ meta?.version }}</span>
      </div>
      <span class="hidden items-center gap-2 text-[12px] text-muted md:flex">
        <i class="relative inline-flex h-2 w-2"><i class="absolute inset-0 animate-ping rounded-full bg-ok opacity-50" /><i class="relative h-2 w-2 rounded-full bg-ok" /></i>
        <span class="num">{{ meta?.listen }}</span>
      </span>
      <div class="ml-auto flex flex-wrap items-center gap-2">
        <Segmented v-model="themePref" :options="themeOptions" :label="t.theme" />
        <Segmented v-model="langPref" :options="langOptions" :label="t.language" />
        <button v-if="canPasskey" class="rounded-lg px-2.5 py-1.5 text-[12px] font-semibold text-muted hover:bg-panel hover:text-fg" :title="t.passkeys(pk.count)" @click="addPasskey">
          {{ t.addPasskey }}<span v-if="pk.count" class="num ml-1 text-[10.5px]">({{ pk.count }})</span>
        </button>
        <button v-if="pk.count" class="rounded-lg px-2.5 py-1.5 text-[12px] font-semibold text-muted hover:bg-panel hover:text-fg" @click="clearPasskeys">{{ t.removePasskeys }}</button>
        <button class="rounded-lg px-2.5 py-1.5 text-[12px] font-semibold text-muted hover:bg-panel hover:text-fg" @click="logout">{{ t.signOut }}</button>
      </div>
    </header>

    <!-- summary panel -->
    <section class="mb-5 grid gap-5 rounded-2xl border border-line bg-panel p-5 sm:p-6 lg:grid-cols-[auto_1fr_auto] lg:items-end">
      <Gauge :score="data?.scan.score ?? 0" :label="t.score" />
      <div class="min-w-0">
        <h1 class="font-display text-[26px] leading-tight font-bold tracking-tight text-balance">
          {{ data ? (findings.length ? t.verdict(data.scan.score) : t.noIssues) : t.scanning }}
        </h1>
        <p class="mt-1 text-[13.5px] text-muted">
          <template v-if="data">
            <span class="num text-fg">{{ findings.length }}</span> {{ t.found.toLowerCase() }} ·
            {{ t.passed }} <span class="num text-fg">{{ passedN }}/{{ data.scan.checked }}</span> {{ t.checks }} ·
            {{ t.lastScan(scannedAt) }}
          </template>
        </p>
        <div class="mt-3 flex flex-wrap gap-1.5">
          <template v-for="s in sevOrder" :key="s"><SevChip v-if="sevCounts[s]" :sev="s" dot :label="`${sevCounts[s]} ${t.sev[s]}`" /></template>
        </div>
      </div>
      <div class="flex flex-wrap gap-2 lg:justify-end">
        <button class="rounded-lg border border-line px-3 py-2 text-[12.5px] font-semibold hover:bg-side disabled:opacity-50" :disabled="busy" @click="undo">{{ t.undo }}</button>
        <button class="inline-flex items-center gap-2 rounded-lg border border-line px-3 py-2 text-[12.5px] font-semibold hover:bg-side disabled:opacity-50" :disabled="busy" @click="load(true)">
          <svg :class="busy ? 'animate-spin' : ''" width="13" height="13" viewBox="0 0 16 16" aria-hidden="true"><path d="M13.5 8A5.5 5.5 0 1 1 8 2.5c1.6 0 3 .7 4 1.7M12.5 1.5v3h-3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" /></svg>
          {{ busy ? t.scanning : t.rescan }}
        </button>
        <button v-if="safeFixes.length" class="rounded-lg bg-accent px-3.5 py-2 text-[12.5px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="askFix(safeFixes)">{{ t.fixSafe(safeFixes.length) }}</button>
      </div>
    </section>

    <div class="grid gap-5 lg:grid-cols-[220px_1fr]">
      <!-- groups -->
      <nav class="lg:sticky lg:top-5 lg:self-start" :aria-label="t.groups">
        <select v-model="cat" class="w-full rounded-lg border border-line bg-panel px-3 py-2 text-sm lg:hidden" :aria-label="t.groups">
          <option value="all">{{ t.all }} ({{ findings.length }})</option>
          <option v-for="c in categories" :key="c" :value="c">{{ t[c] }} ({{ counts[c] || 0 }})</option>
          <option value="checked">{{ t.checkedView }} ({{ sources.length }})</option>
        </select>
        <div class="hidden gap-0.5 lg:grid">
          <button class="flex items-center justify-between rounded-lg px-3 py-2 text-left text-[13.5px] transition-colors"
            :class="cat === 'all' ? 'bg-panel font-semibold shadow-sm ring-1 ring-line' : 'text-muted hover:bg-panel/60 hover:text-fg'" @click="cat = 'all'">
            {{ t.all }} <span class="num text-[11.5px] text-muted">{{ findings.length }}</span>
          </button>
          <div class="eyebrow px-3 pt-4 pb-1.5">{{ t.groups }}</div>
          <button v-for="c in categories" :key="c" class="flex items-center justify-between rounded-lg px-3 py-2 text-left text-[13.5px] transition-colors"
            :class="cat === c ? 'bg-panel font-semibold shadow-sm ring-1 ring-line' : 'text-muted hover:bg-panel/60 hover:text-fg'" @click="cat = c">
            {{ t[c] }}
            <span class="num text-[11.5px]" :class="counts[c] ? 'text-fg' : 'text-muted/60'">{{ counts[c] || 0 }}</span>
          </button>
          <div class="my-2 border-t border-line" />
          <button class="flex items-center justify-between rounded-lg px-3 py-2 text-left text-[13.5px] transition-colors"
            :class="cat === 'checked' ? 'bg-panel font-semibold shadow-sm ring-1 ring-line' : 'text-muted hover:bg-panel/60 hover:text-fg'" @click="cat = 'checked'">
            {{ t.checkedView }} <span class="num text-[11.5px] text-muted">{{ sources.length }}</span>
          </button>
        </div>
      </nav>

      <!-- findings -->
      <main class="grid min-w-0 content-start gap-3">
        <template v-if="cat === 'checked'">
          <h2 class="font-display text-lg font-bold">{{ t.checkedTitle }}</h2>
          <div class="overflow-hidden rounded-xl border border-line bg-panel">
            <div v-for="(s, i) in sources" :key="s.name" class="rise grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-0.5 border-b border-line px-4 py-3 last:border-b-0 sm:grid-cols-[minmax(0,1fr)_9rem_auto]" :style="{ animationDelay: `${Math.min(i, 20) * 20}ms` }">
              <div class="min-w-0">
                <div class="text-[13.5px] font-medium">{{ s.label }}</div>
                <div class="text-[12px] text-muted"><span>{{ t[s.category] || '' }}</span><span v-if="s.detail"> · {{ s.detail }}</span></div>
              </div>
              <div class="num hidden text-right text-[12px] text-muted sm:block">{{ s.state === 'skipped' ? '—' : t.items(s.items) }}</div>
              <span class="rounded-md px-2 py-[3px] font-mono text-[10.5px] font-semibold uppercase tracking-[.08em]" :class="stCls[s.state]">
                {{ s.state === 'ok' ? t.stOk : s.state === 'issues' ? t.stIssues(s.issues) : s.state === 'skipped' ? t.stSkipped : t.stError }}
              </span>
            </div>
          </div>
        </template>
        <template v-else>
          <div v-if="data && !groups.length" class="rounded-xl border border-dashed border-line bg-panel/60 p-8 text-center text-muted">{{ t.noIssues }}</div>
          <FindingCard v-for="(g, i) in groups" :key="g.first.rule_id" :group="g" :index="i" :t="t" :busy="busy" @fix="askFix" />
        </template>
        <p class="pt-3 text-[12px] text-muted">{{ t.local }}</p>
      </main>
    </div>

    <!-- fix confirmation -->
    <div v-if="sheet" class="fixed inset-0 z-10 grid place-items-center bg-black/45 p-4 backdrop-blur-[2px]" @click.self="sheet = null">
      <section class="rise grid max-h-[85vh] w-full max-w-lg gap-3 overflow-y-auto rounded-2xl border border-line bg-panel p-5 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="sheet-title">
        <h2 id="sheet-title" class="font-display text-lg font-bold">{{ t.sheetTitle(sheetOn) }}</h2>
        <label v-for="x in sheet" :key="x.f.key" class="grid grid-cols-[18px_1fr] gap-3 border-t border-line pt-3">
          <input v-model="x.on" type="checkbox" class="mt-1 h-4 w-4 accent-[var(--color-accent)]" />
          <span class="min-w-0">
            <span class="block text-[13.5px] font-medium break-words">{{ x.f.title }}</span>
            <span class="mt-0.5 block font-mono text-[12px] text-muted break-all">$ {{ (x.f.plan || []).join(' && ') }}</span>
            <span class="block text-[12px]" :class="x.f.undoable ? 'text-ok' : 'text-med'">{{ x.f.undoable ? t.undoable : t.noUndo }}</span>
          </span>
        </label>
        <div class="flex justify-end gap-2 pt-2">
          <button class="rounded-lg border border-line px-3.5 py-2 text-[12.5px] font-semibold hover:bg-side" @click="sheet = null">{{ t.cancel }}</button>
          <button class="rounded-lg bg-accent px-3.5 py-2 text-[12.5px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="!sheetOn" @click="applyFix">{{ t.apply(sheetOn) }}</button>
        </div>
      </section>
    </div>

    <div v-if="toast" class="rise fixed right-4 bottom-4 left-4 z-20 mx-auto max-w-md rounded-xl bg-fg px-4 py-3 text-[13.5px] text-page shadow-xl sm:left-auto" role="status">{{ toast }}</div>
  </div>
</template>
