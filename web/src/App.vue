<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api } from './api.js'
import { dict } from './i18n.js'
import { passkeySupported } from './passkey.js'
import Dial from './components/Dial.vue'
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
  busy.value = true
  try { data.value = await (force ? api.rescan(lang.value) : api.scan(lang.value)) } catch (e) { fail(e) } finally { busy.value = false }
}

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
const onboarding = ref(false)
async function onbAdd() { onboarding.value = false; await addPasskey() }
function onbLater() { onboarding.value = false; save('sw.pkLater', '1') }

async function clearPasskeys() { try { await api.clearPasskeys(); pk.value.count = 0; say(t.value.passkeysRemoved) } catch (e) { fail(e) } }

onMounted(async () => {
  await refreshPasskey()
  try { meta.value = await api.meta() } catch (e) { if (e.status === 401) { signedOut.value = true; return } }
  if (canPasskey.value && !pk.value.count && !pref('sw.pkLater')) onboarding.value = true
  load()
})

const findings = computed(() => data.value?.findings || [])
const ignored = computed(() => data.value?.ignored || [])
const sources = computed(() => data.value?.sources || [])
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
const safeFixes = computed(() => findings.value.filter(f => f.can_fix))
const passedN = computed(() => (data.value?.scan.passed || []).length)
const fmtTime = iso => (iso ? new Date(iso).toLocaleTimeString(lang.value, { hour: '2-digit', minute: '2-digit' }) : '')
const fmtDate = iso => new Date(iso).toLocaleDateString(lang.value, { day: 'numeric', month: 'short', year: 'numeric' })
const listTitle = computed(() => (cat.value === 'all' ? t.value.issuesTitle : cat.value === 'checked' ? t.value.checkedTitle : cat.value === 'ignored' ? t.value.ignoredTitle : t.value[cat.value]))

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
function onKey(e) { if (e.key === 'Escape') sheet.value = null }
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
        <span class="flex items-center gap-2.5 text-[15px] font-extrabold tracking-[.06em] uppercase">
          <svg width="20" height="22" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" fill="var(--color-accent)" /></svg>
          Security Warden
        </span>
        <span class="hidden items-center gap-2 text-[13px] text-muted lg:flex">
          <i class="h-2 w-2 rounded-full bg-ok shadow-[0_0_0_4px_var(--color-ok-bg)]" />
          {{ t.watching }} · {{ data?.scan.host || '' }} · {{ t.lastScan(fmtTime(data?.scanned_at)) }}
        </span>
        <div class="ml-auto flex flex-wrap items-center gap-2">
          <Segmented v-model="themePref" :options="themeOptions" :label="t.theme" />
          <Segmented v-model="langPref" :options="langOptions" :label="t.language" />
          <button v-if="canPasskey" class="rounded-[10px] px-2.5 py-1.5 text-[13px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="addPasskey">
            {{ t.addPasskey }}<span v-if="pk.count" class="num ml-1">({{ pk.count }})</span>
          </button>
          <button v-if="pk.count" class="rounded-[10px] px-2.5 py-1.5 text-[13px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="clearPasskeys">{{ t.removePasskeys }}</button>
          <button class="rounded-[10px] px-2.5 py-1.5 text-[13px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="logout">{{ t.signOut }}</button>
        </div>
      </div>
    </header>

    <div class="mx-auto grid max-w-[1280px] gap-5 px-4 py-5 sm:px-6 lg:grid-cols-[320px_1fr]">
      <!-- left: score, counts, groups -->
      <aside class="grid content-start gap-5">
        <section class="panel p-5">
          <Dial :score="data?.scan.score ?? 0" :label="t.score" />
          <p class="mt-3 text-center text-[15px] font-semibold">{{ data ? t.verdict(data.scan.score) : t.scanning }}</p>
          <div class="mt-4 grid grid-cols-2 gap-2.5">
            <div class="rounded-xl border border-line bg-crit-bg px-3 py-2.5"><b class="num block text-[24px] leading-tight font-extrabold text-crit">{{ sevCounts.critical || 0 }}</b><span class="caps">{{ t.statsCritical }}</span></div>
            <div class="rounded-xl border border-line bg-high-bg px-3 py-2.5"><b class="num block text-[24px] leading-tight font-extrabold text-high">{{ sevCounts.high || 0 }}</b><span class="caps">{{ t.statsHigh }}</span></div>
            <div class="rounded-xl border border-line px-3 py-2.5"><b class="num block text-[24px] leading-tight font-extrabold text-med">{{ sevCounts.medium || 0 }}</b><span class="caps">{{ t.statsMedium }}</span></div>
            <div class="rounded-xl border border-line px-3 py-2.5"><b class="num block text-[24px] leading-tight font-extrabold text-ok">{{ passedN }}<span class="text-[14px] font-semibold text-muted">/{{ data?.scan.checked || 0 }}</span></b><span class="caps">{{ t.statsPassed }}</span></div>
          </div>
          <div class="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-1">
            <button v-if="safeFixes.length" class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50" :disabled="busy" @click="askFix(safeFixes)">{{ t.fixSafe(safeFixes.length) }}</button>
            <div class="grid grid-cols-2 gap-2">
              <button class="inline-flex items-center justify-center gap-2 rounded-xl border border-line bg-panel2 px-3 py-2.5 text-[13.5px] font-semibold hover:text-accent disabled:opacity-50" :disabled="busy" @click="load(true)">
                <svg :class="busy ? 'animate-spin' : ''" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true"><path d="M13.5 8A5.5 5.5 0 1 1 8 2.5c1.6 0 3 .7 4 1.7M12.5 1.5v3h-3" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" /></svg>
                {{ busy ? t.scanning : t.rescan }}
              </button>
              <button class="rounded-xl border border-line bg-panel2 px-3 py-2.5 text-[13.5px] font-semibold hover:text-accent disabled:opacity-50" :disabled="busy" @click="undo">{{ t.undoShort }}</button>
            </div>
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
          <span v-if="cat !== 'checked' && cat !== 'ignored'" class="num rounded-full bg-panel2 px-2.5 py-0.5 text-[13px] font-bold text-muted ring-1 ring-line">{{ groups.length }}</span>
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
          <p v-if="data && !groups.length" class="px-5 py-10 text-center text-muted">{{ t.noIssues }}</p>
          <div class="pl-5">
            <FindingRow v-for="(g, i) in groups" :key="g.first.rule_id" :group="g" :index="i" :t="t" :busy="busy" @fix="askFix" @ignore="ignoreFindings" />
          </div>
        </div>
        <p class="border-t border-line px-5 py-3 text-[13px] text-muted">{{ t.local }}</p>
      </main>
    </div>

    <!-- first sign-in: offer a passkey -->
    <div v-if="onboarding" class="fixed inset-0 z-20 grid place-items-center bg-black/55 p-4 backdrop-blur-sm">
      <section class="panel rise grid w-full max-w-md gap-4 p-7 text-center shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="onb-title">
        <div class="mx-auto grid h-14 w-14 place-items-center rounded-2xl bg-accent-soft text-accent">
          <svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="4" fill="none" stroke="currentColor" stroke-width="2" /><path d="M2 21c0-3.9 3.1-7 7-7 1.5 0 2.9.5 4 1.3M17 11a3 3 0 1 1 0 6 3 3 0 0 1 0-6Zm0 6v5m0-2h2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
        </div>
        <h2 id="onb-title" class="text-[20px] font-bold">{{ t.onbTitle }}</h2>
        <p class="text-[15px] text-muted">{{ t.onbText }}</p>
        <div class="grid gap-2 pt-1">
          <button class="rounded-xl bg-accent px-4 py-3 text-[15px] font-semibold text-accent-ink hover:brightness-110" @click="onbAdd">{{ t.onbAdd }}</button>
          <button class="rounded-xl px-4 py-2.5 text-[14px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="onbLater">{{ t.onbLater }}</button>
        </div>
        <p class="text-[12.5px] text-muted">{{ t.onbSafe }}</p>
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
      <button class="-mr-1 rounded px-1.5 font-bold opacity-80 hover:opacity-100" :aria-label="t.close" @click="toast = ''">✕</button>
    </div>
  </div>
</template>
