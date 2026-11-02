<script setup>
import { computed, ref } from 'vue'
import SevChip from './SevChip.vue'

// One problem (a rule, with every place it was found). Collapsed: the line
// you scan. Open: why, how to fix, where else, and the actions.
const props = defineProps({ group: Object, t: Object, busy: Boolean, index: Number })
const emit = defineEmits(['fix', 'ignore'])
const open = ref(false)
const menu = ref(false)
const f = computed(() => props.group.first)
// Severity shows as a soft tint behind the whole row.
// Each card's header carries its severity colour; the opened body stays neutral.
const tint = { critical: 'bg-crit-bg', high: 'bg-high-bg', medium: 'bg-med-bg', low: 'bg-low-bg', info: 'bg-info-bg' }
const all = computed(() => [props.group.first, ...props.group.rest])
// Short headline: the problem without the specific file or name ("X: detail").
const parts = computed(() => {
  const i = f.value.title.indexOf(': ')
  return i > 0 ? [f.value.title.slice(0, i), f.value.title.slice(i + 2)] : [f.value.title, '']
})
const title = computed(() => parts.value[0])
const sub = computed(() => (props.group.rest.length ? props.t.places(props.group.rest.length + 1) : parts.value[1]))
function ignore(days) { menu.value = false; emit('ignore', all.value, days) }
</script>

<template>
  <div class="rise overflow-hidden rounded-xl bg-panel2 ring-1 ring-line transition-shadow hover:ring-accent/50" :style="{ animationDelay: `${Math.min(index, 14) * 28}ms` }">
    <div class="grid grid-cols-[1fr_auto] items-center gap-4 py-3.5 pr-3 pl-4" :class="tint[f.severity]">
      <button class="min-w-0 text-left" :aria-expanded="open" @click="open = !open">
        <span class="block text-[16px] leading-snug font-semibold break-words">{{ title }}</span>
        <span v-if="sub" class="mt-0.5 block truncate text-[13.5px] text-muted">{{ sub }}</span>
      </button>
      <div class="flex items-center gap-3">
        <button v-if="group.fixable.length" class="rounded-[10px] bg-accent px-3.5 py-1.5 text-[13px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50"
          :disabled="busy" @click="emit('fix', group.fixable)">{{ t.fix }}</button>
        <button class="grid h-8 w-8 place-items-center rounded-lg text-muted hover:bg-panel2 hover:text-fg" :aria-label="open ? t.showLess : t.details" @click="open = !open">
          <svg width="14" height="14" viewBox="0 0 16 16" :class="open ? 'rotate-180' : ''" class="transition-transform"><path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
        </button>
      </div>
    </div>

    <div v-if="open" class="grid gap-3 border-t border-line/70 px-4 pt-3.5 pb-4">
      <div class="flex flex-wrap items-center gap-2">
        <SevChip :sev="f.severity" :label="t.sev[f.severity]" />
        <span class="ml-auto font-mono text-[12px] text-muted">{{ f.rule_id }}</span>
      </div>
      <p v-if="parts[1] && !group.rest.length" class="font-mono text-[13px] break-all text-muted">{{ parts[1] }}</p>
      <p class="max-w-[76ch] text-[15px] leading-relaxed">{{ f.explain }}</p>
      <div v-if="f.plan" class="overflow-x-auto rounded-xl border border-line bg-panel2 px-3.5 py-2.5 font-mono text-[13px] whitespace-pre">{{ f.plan.map(p => '$ ' + p).join('\n') }}</div>
      <p v-else class="flex gap-2 rounded-xl bg-accent-soft px-3.5 py-2.5 text-[14.5px] font-medium"><span class="font-bold text-accent">→</span><span class="break-words">{{ f.fix }}</span></p>
      <div v-if="group.rest.length">
        <div class="caps mb-1.5">{{ t.places(group.rest.length + 1) }}</div>
        <ul class="grid max-h-56 gap-1 overflow-y-auto border-l-2 border-line pl-3 font-mono text-[12.5px] text-muted">
          <li v-for="x in all" :key="x.key" class="break-all">{{ x.title.includes(': ') ? x.title.slice(x.title.indexOf(': ') + 2) : x.title }}</li>
        </ul>
      </div>
      <div class="relative flex flex-wrap items-center gap-2 pt-1">
        <span v-if="f.needs_root" class="text-[13px] text-muted">{{ t.needsAdmin }}</span>
        <span v-else-if="f.plan" class="text-[13px] text-muted">{{ f.undoable ? t.undoable : t.noUndo }}</span>
        <button class="ml-auto rounded-[10px] border border-line px-3 py-1.5 text-[13px] font-semibold text-muted hover:bg-panel2 hover:text-fg" :aria-expanded="menu" @click="menu = !menu">
          {{ t.ignore }} ▾
        </button>
        <div v-if="menu" class="absolute right-0 bottom-10 z-10 grid min-w-48 overflow-hidden rounded-xl border border-line bg-panel py-1 text-[13.5px] shadow-2xl" role="menu">
          <button v-for="d in [1, 7, 30]" :key="d" class="px-4 py-2 text-left hover:bg-panel2" role="menuitem" @click="ignore(d)">{{ t.ignoreFor(d) }}</button>
          <button v-if="f.severity !== 'critical'" class="px-4 py-2 text-left hover:bg-panel2" role="menuitem" @click="ignore(0)">{{ t.ignoreForever }}</button>
          <div v-else class="px-4 py-2 text-[12px] text-muted">{{ t.criticalMax }}</div>
        </div>
      </div>
    </div>
  </div>
</template>
