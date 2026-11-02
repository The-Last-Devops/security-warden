<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api } from './api.js'
import { dict } from './i18n.js'
import ScoreRing from './components/ScoreRing.vue'
import SevChip from './components/SevChip.vue'
import FindingCard from './components/FindingCard.vue'

const stored = (() => { try { return localStorage.getItem('sw.lang') } catch { return null } })()
const lang = ref(stored || ((navigator.language || 'en').startsWith('vi') ? 'vi' : 'en'))
const t = computed(() => dict[lang.value] || dict.en)
const meta = ref(null)
const data = ref(null)
const busy = ref(false)
const toast = ref('')
const signedOut = ref(false)
const cat = ref('all')
const sheet = ref(null) // findings waiting for confirmation

const categories = ['secrets', 'exposure', 'settings', 'persistence', 'ai', 'devtools', 'software']
const sevOrder = ['critical', 'high', 'medium', 'low', 'info']

function say(msg) { toast.value = msg; setTimeout(() => { if (toast.value === msg) toast.value = '' }, 4000) }

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
  try { meta.value = await api.meta() } catch (e) { if (e.status === 401) { signedOut.value = true; return } }
  if (!stored && meta.value?.lang) lang.value = meta.value.lang
  load()
})
watch(lang, l => { try { localStorage.setItem('sw.lang', l) } catch {} ; document.documentElement.lang = l; if (meta.value) load() })

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
// One card per rule, like the terminal report.
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
const scannedAt = computed(() => data.value?.scanned_at ? new Date(data.value.scanned_at).toLocaleTimeString(lang.value) : '')

function askFix(list) { sheet.value = list.map(f => ({ f, on: true })) }
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
    await load(true)
  } catch (e) { say(`${t.value.error}: ${e.message}`) }
}
async function logout() { try { await api.logout() } catch {} ; signedOut.value = true }
</script>

<template>
  <div v-if="signedOut" class="mx-auto mt-[15vh] max-w-md px-4 text-center">
    <h1 class="mb-2 text-xl font-semibold">security-warden</h1>
    <p class="text-muted">{{ t.signedOut }}</p>
  </div>

  <div v-else class="mx-auto flex min-h-full max-w-[1180px] flex-col px-4 py-5 sm:py-7">
    <div class="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-line bg-win shadow-sm">
      <!-- title bar -->
      <header class="flex items-center gap-3 border-b border-line bg-panel px-4 py-2.5">
        <svg width="18" height="20" viewBox="0 0 20 22" aria-hidden="true"><path d="M10 1 2 4v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V4z" class="fill-accent" /></svg>
        <span class="font-semibold">security-warden</span>
        <span class="hidden text-xs text-muted sm:inline">{{ meta?.version }}</span>
        <span class="ml-auto hidden items-center gap-1.5 text-xs text-muted sm:flex">
          <i class="inline-block h-2 w-2 rounded-full bg-ok"></i>{{ meta ? t.serving(meta.listen) : '' }}
        </span>
        <div class="flex overflow-hidden rounded-md border border-line text-xs font-semibold" role="group" aria-label="Language">
          <button v-for="l in ['en', 'vi']" :key="l" class="px-2 py-1" :class="lang === l ? 'bg-accent-soft text-accent' : 'text-muted'" @click="lang = l">{{ l.toUpperCase() }}</button>
        </div>
        <button class="text-xs font-semibold text-muted hover:text-fg" @click="logout">{{ t.signOut }}</button>
      </header>

      <div class="grid min-h-0 flex-1 md:grid-cols-[210px_1fr]">
        <!-- sidebar -->
        <nav class="hidden content-start gap-0.5 border-r border-line bg-side p-2 md:grid" aria-label="Groups">
          <button class="flex items-center justify-between rounded-md px-2.5 py-1.5 text-left text-[13px]"
            :class="cat === 'all' ? 'bg-accent-soft font-semibold text-accent' : ''" @click="cat = 'all'">
            {{ t.all }} <span class="text-[11.5px] text-muted tabular-nums">{{ findings.length }}</span>
          </button>
          <div class="px-2.5 pt-3 pb-1 text-[11px] font-semibold tracking-wider text-muted uppercase">{{ t.groups }}</div>
          <button v-for="c in categories" :key="c" class="flex items-center justify-between rounded-md px-2.5 py-1.5 text-left text-[13px]"
            :class="cat === c ? 'bg-accent-soft font-semibold text-accent' : ''" @click="cat = c">
            {{ t[c] }} <span class="text-[11.5px] text-muted tabular-nums">{{ counts[c] || 0 }}</span>
          </button>
        </nav>

        <!-- content -->
        <main class="grid min-w-0 content-start gap-3.5 p-4 sm:p-5">
          <select v-model="cat" class="rounded-md border border-line bg-panel px-2 py-1.5 text-sm md:hidden" aria-label="Group">
            <option value="all">{{ t.all }} ({{ findings.length }})</option>
            <option v-for="c in categories" :key="c" :value="c">{{ t[c] }} ({{ counts[c] || 0 }})</option>
          </select>

          <section class="flex flex-wrap items-center gap-4">
            <ScoreRing :score="data?.scan.score ?? 0" />
            <div class="min-w-[14rem] flex-1">
              <h1 class="text-xl font-semibold tracking-tight">
                {{ data ? (findings.length ? t.issues(findings.length) : t.noIssues) : t.scanning }}
              </h1>
              <p class="text-[13px] text-muted">
                <template v-if="data">{{ t.verdict(data.scan.score) }} · {{ t.checked(data.scan.checked, (data.scan.passed || []).length) }} · {{ t.lastScan(scannedAt) }}</template>
              </p>
              <div class="mt-1.5 flex flex-wrap gap-1.5">
                <template v-for="s in sevOrder" :key="s"><SevChip v-if="sevCounts[s]" :sev="s" :label="`${sevCounts[s]} ${t.sev[s]}`" /></template>
              </div>
            </div>
            <div class="flex flex-wrap gap-2">
              <button class="rounded-lg border border-line bg-panel px-3 py-1.5 text-xs font-semibold" :disabled="busy" @click="undo">{{ t.undo }}</button>
              <button class="rounded-lg border border-line bg-panel px-3 py-1.5 text-xs font-semibold disabled:opacity-50" :disabled="busy" @click="load(true)">{{ busy ? t.scanning : t.rescan }}</button>
              <button v-if="safeFixes.length" class="rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50" :disabled="busy" @click="askFix(safeFixes)">{{ t.fixSafe(safeFixes.length) }}</button>
            </div>
          </section>

          <FindingCard v-for="g in groups" :key="g.first.rule_id" :group="g" :t="t" :busy="busy" @fix="askFix" />
          <p class="pt-2 text-xs text-muted">{{ t.local }}</p>
        </main>
      </div>
    </div>

    <!-- fix confirmation -->
    <div v-if="sheet" class="fixed inset-0 z-10 grid place-items-center bg-black/40 p-4" @click.self="sheet = null">
      <section class="grid w-full max-w-lg gap-3 rounded-xl border border-line bg-panel p-5 shadow-xl" role="dialog" aria-modal="true">
        <h2 class="text-base font-semibold">{{ t.sheetTitle(sheet.filter(x => x.on).length) }}</h2>
        <label v-for="x in sheet" :key="x.f.key" class="grid grid-cols-[18px_1fr] gap-2.5 border-t border-line pt-2.5">
          <input v-model="x.on" type="checkbox" class="mt-1 accent-[var(--color-accent)]" />
          <span class="min-w-0">
            <span class="block text-[13.5px] font-medium break-words">{{ x.f.title }}</span>
            <span class="block font-mono text-[12px] text-muted break-all">{{ (x.f.plan || []).join(' ') }}</span>
            <span class="block text-[12px] text-muted">{{ x.f.undoable ? t.undoable : t.noUndo }}</span>
          </span>
        </label>
        <div class="flex justify-end gap-2 pt-1">
          <button class="rounded-lg border border-line px-3 py-1.5 text-xs font-semibold" @click="sheet = null">{{ t.cancel }}</button>
          <button class="rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white" @click="applyFix">{{ t.apply(sheet.filter(x => x.on).length) }}</button>
        </div>
      </section>
    </div>

    <div v-if="toast" class="fixed right-4 bottom-4 left-4 z-20 mx-auto max-w-md rounded-lg bg-fg px-4 py-2.5 text-sm text-page shadow-lg sm:left-auto" role="status">{{ toast }}</div>
  </div>
</template>
