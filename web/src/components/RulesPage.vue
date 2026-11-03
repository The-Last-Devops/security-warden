<script setup>
// Rules & sources: every check and every source with the fields a rule can
// read, searchable. A reference for people who want to write a rule.
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'
import SevChip from './SevChip.vue'
import TierBadge from './TierBadge.vue'

const props = defineProps({ t: { type: Object, required: true }, lang: { type: String, required: true } })
const emit = defineEmits(['close'])

const data = ref(null)
const err = ref('')
const q = ref('')
const open = ref({})
const tab = ref('rules')

onMounted(async () => {
  try { data.value = await api.sources(props.lang) } catch (e) { err.value = e.message }
})

const needle = computed(() => q.value.trim().toLowerCase())
const has = (...xs) => xs.some(x => String(x ?? '').toLowerCase().includes(needle.value))
const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

const rules = computed(() => {
  const all = [...(data.value?.rules || [])].sort((a, b) => (sevRank[a.severity] - sevRank[b.severity]) || a.id.localeCompare(b.id))
  if (!needle.value) return all
  return all.filter(r => has(r.id, r.title, r.check, r.source, r.severity, r.tier, r.category))
})
const sources = computed(() => {
  const all = data.value?.sources || []
  if (!needle.value) return all
  return all.filter(s => has(s.name, s.label, s.category, s.category_label) || (s.fields || []).some(f => has(f.name, f.desc)))
})
const plat = ps => (ps || []).map(p => props.t.platformNames[p] || p).join(', ')
// A search that names a field opens the sources that have it.
const isOpen = s => open.value[s.name] || (needle.value && (s.fields || []).some(f => has(f.name)))
</script>

<template>
  <div class="fixed inset-0 z-40 grid place-items-start overflow-y-auto bg-black/50 px-4 py-[6vh] backdrop-blur-sm" @click.self="emit('close')" @keydown.esc="emit('close')">
    <section class="panel rise mx-auto grid w-full max-w-[860px] min-w-0 gap-4 p-5 shadow-2xl sm:p-6" role="dialog" aria-modal="true" aria-labelledby="rules-title">
      <div class="flex items-center gap-3">
        <h2 id="rules-title" class="text-[19px] font-extrabold">{{ t.rulesTitle }}</h2>
        <button class="ml-auto grid h-9 w-9 shrink-0 place-items-center rounded-lg text-muted ring-1 ring-line hover:text-fg" :aria-label="t.close" @click="emit('close')">✕</button>
      </div>
      <p class="text-[14px] text-muted">
        {{ t.rulesIntro }}
        <a v-if="data?.docs_url" :href="data.docs_url" target="_blank" rel="noopener noreferrer" class="font-semibold text-accent hover:underline">{{ t.rulesHowTo }} ↗</a>
      </p>

      <input v-model="q" type="search" :placeholder="t.rulesSearch" :aria-label="t.rulesSearch"
        class="w-full min-w-0 rounded-[10px] bg-panel2 px-3.5 py-2.5 text-[15px] ring-1 ring-line outline-none placeholder:text-muted focus:ring-accent" />

      <div class="inline-flex justify-self-start rounded-[10px] bg-panel2 p-0.5 ring-1 ring-line" role="group">
        <button v-for="v in ['rules', 'sources']" :key="v" class="rounded-lg px-3 py-1 text-[13px] font-semibold"
          :class="tab === v ? 'bg-panel text-fg shadow-sm ring-1 ring-line' : 'text-muted hover:text-fg'" :aria-pressed="tab === v" @click="tab = v">
          {{ v === 'rules' ? t.rulesList(rules.length) : t.sourcesList(sources.length) }}
        </button>
      </div>

      <p v-if="err" class="rounded-xl bg-crit-bg px-4 py-3 text-[14px] text-crit">{{ t.error }}: {{ err }}</p>
      <p v-else-if="!data" class="py-8 text-center text-muted">{{ t.loading }}</p>

      <template v-else-if="tab === 'rules'">
        <p v-if="!rules.length" class="py-8 text-center text-muted">{{ t.noMatch }}</p>
        <ul class="grid gap-2">
          <li v-for="r in rules" :key="r.id" class="grid min-w-0 gap-1 rounded-xl bg-panel2 px-4 py-3 ring-1 ring-line">
            <div class="flex flex-wrap items-center gap-2">
              <SevChip :sev="r.severity" :label="t.sev[r.severity]" />
              <TierBadge :tier="r.tier" :t="t" />
              <span class="min-w-0 font-mono text-[12.5px] break-all text-muted">{{ r.id }}</span>
            </div>
            <span class="text-[15px] font-semibold break-words">{{ r.title }}</span>
            <span class="text-[13.5px] text-muted break-words">✓ {{ r.check }}</span>
            <span class="text-[12.5px] text-muted"><span class="font-mono">{{ r.source }}</span> · {{ plat(r.platforms) }}</span>
          </li>
        </ul>
      </template>

      <template v-else>
        <p v-if="!sources.length" class="py-8 text-center text-muted">{{ t.noMatch }}</p>
        <ul class="grid gap-2">
          <li v-for="s in sources" :key="s.name" class="min-w-0 overflow-hidden rounded-xl bg-panel2 ring-1 ring-line">
            <button class="grid w-full min-w-0 gap-0.5 px-4 py-3 text-left" :aria-expanded="!!isOpen(s)" @click="open[s.name] = !isOpen(s)">
              <span class="flex items-center gap-2">
                <span class="min-w-0 flex-1 text-[15px] font-semibold break-words">{{ s.label }}</span>
                <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true" class="shrink-0 text-muted transition-transform" :class="isOpen(s) ? 'rotate-180' : ''"><path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
              </span>
              <span class="text-[12.5px] text-muted break-words">
                <span class="font-mono text-fg/80">{{ s.name }}</span> · {{ s.category_label || s.category }} · {{ plat(s.platforms) }} · {{ t.rulesCount(s.rules) }} · {{ t.fieldsCount((s.fields || []).length) }}
              </span>
            </button>
            <div v-if="isOpen(s)" class="overflow-x-auto border-t border-line">
              <table class="w-full min-w-[520px] text-left text-[13px]">
                <thead class="text-[11.5px] tracking-[.08em] text-muted uppercase">
                  <tr><th class="px-4 py-2 font-bold">{{ t.fieldName }}</th><th class="px-2 py-2 font-bold">{{ t.fieldType }}</th><th class="px-2 py-2 font-bold">{{ t.fieldDesc }}</th><th class="px-4 py-2 font-bold">{{ t.fieldExample }}</th></tr>
                </thead>
                <tbody>
                  <tr v-for="f in s.fields" :key="f.name" class="border-t border-line align-top">
                    <td class="px-4 py-2 font-mono font-semibold whitespace-nowrap">{{ f.name }}</td>
                    <td class="px-2 py-2 font-mono text-muted">{{ f.type }}</td>
                    <td class="px-2 py-2">{{ f.desc }}</td>
                    <td class="px-4 py-2 font-mono break-all text-muted">{{ f.example }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </li>
        </ul>
      </template>
    </section>
  </div>
</template>
