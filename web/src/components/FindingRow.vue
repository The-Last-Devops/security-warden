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
const rail = { critical: 'bg-rail-crit', high: 'bg-rail-high', medium: 'bg-rail-med', low: 'bg-rail-low', info: 'bg-rail-info' }
const all = computed(() => [props.group.first, ...props.group.rest])
const title = computed(() => (props.group.rest.length ? `${f.value.title}` : f.value.title))
const sub = computed(() => (f.value.plan ? `$ ${f.value.plan[0]}` : f.value.fix))
function ignore(days) { menu.value = false; emit('ignore', all.value, days) }
</script>

<template>
  <div class="rise border-t border-line first:border-t-0" :style="{ animationDelay: `${Math.min(index, 14) * 28}ms` }">
    <div class="grid grid-cols-[4px_1fr_auto] items-center gap-4 py-4 pr-4">
      <span class="self-stretch rounded-full" :class="rail[f.severity]" aria-hidden="true" />
      <button class="min-w-0 text-left" :aria-expanded="open" @click="open = !open">
        <span class="flex flex-wrap items-baseline gap-x-2">
          <span class="text-[16.5px] leading-snug font-semibold break-words">{{ title }}</span>
          <span v-if="group.rest.length" class="num rounded-md bg-panel2 px-1.5 text-[12px] font-bold text-muted ring-1 ring-line">+{{ group.rest.length }}</span>
        </span>
        <span class="mt-1 block truncate text-[14px] text-muted" :class="f.plan ? 'font-mono text-[13px]' : ''">{{ sub }}</span>
      </button>
      <div class="flex items-center gap-2">
        <button v-if="group.fixable.length" class="rounded-[10px] bg-accent px-3.5 py-1.5 text-[13px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50"
          :disabled="busy" @click="emit('fix', group.fixable)">{{ group.fixable.length > 1 ? t.fixN(group.fixable.length) : t.fix }}</button>
        <SevChip v-else :sev="f.severity" :label="t.sev[f.severity]" />
        <button class="grid h-8 w-8 place-items-center rounded-lg text-muted hover:bg-panel2 hover:text-fg" :aria-label="open ? t.showLess : t.details" @click="open = !open">
          <svg width="14" height="14" viewBox="0 0 16 16" :class="open ? 'rotate-180' : ''" class="transition-transform"><path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
        </button>
      </div>
    </div>

    <div v-if="open" class="grid gap-3 pr-4 pb-4 pl-8">
      <div class="flex flex-wrap items-center gap-2">
        <SevChip :sev="f.severity" :label="t.sev[f.severity]" />
        <span class="font-mono text-[12px] text-muted">{{ f.rule_id }}</span>
      </div>
      <p class="max-w-[76ch] text-[15px] leading-relaxed">{{ f.explain }}</p>
      <div v-if="f.plan" class="overflow-x-auto rounded-xl border border-line bg-panel2 px-3.5 py-2.5 font-mono text-[13px] whitespace-pre">{{ f.plan.map(p => '$ ' + p).join('\n') }}</div>
      <p v-else class="flex gap-2 rounded-xl bg-accent-soft px-3.5 py-2.5 text-[14.5px] font-medium"><span class="font-bold text-accent">→</span><span class="break-words">{{ f.fix }}</span></p>
      <div v-if="group.rest.length">
        <div class="caps mb-1.5">{{ t.sameIssue(group.rest.length) }}</div>
        <ul class="grid max-h-56 gap-1 overflow-y-auto border-l-2 border-line pl-3 text-[13.5px] text-muted">
          <li v-for="x in group.rest" :key="x.key" class="break-words">{{ x.title }}</li>
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
