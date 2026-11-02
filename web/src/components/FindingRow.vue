<script setup>
import { computed, ref } from 'vue'
import SevChip from './SevChip.vue'
import FixSteps from './FixSteps.vue'
import CodeLine from './CodeLine.vue'
import PerPlace from './PerPlace.vue'
import { perPlace, placeOf } from '../fixgroup.js'

// One problem (a rule, with every place it was found). Collapsed: the line
// you scan. Open: why, how to fix, where else, and the actions.
const props = defineProps({ group: Object, t: Object, busy: Boolean, index: Number })
const emit = defineEmits(['fix', 'ignore'])
const open = ref(false)
const f = computed(() => props.group.first)
// Severity is a thin bar at the left edge; the row itself stays neutral, so
// a long list of one severity does not turn into one block of colour.
const bar = { critical: 'bg-crit', high: 'bg-high', medium: 'bg-med', low: 'bg-low', info: 'bg-info' }
const all = computed(() => [props.group.first, ...props.group.rest])
const pp = computed(() => perPlace(all.value))
// Short headline: the problem without the specific file or name ("X: detail").
const parts = computed(() => {
  const i = f.value.title.indexOf(': ')
  return i > 0 ? [f.value.title.slice(0, i), f.value.title.slice(i + 2)] : [f.value.title, '']
})
const title = computed(() => parts.value[0])
// The second line says where: the place, or the first two places.
const sub = computed(() => {
  if (!props.group.rest.length) return parts.value[1]
  const shown = all.value.slice(0, 2).map(placeOf).join(' · ')
  return all.value.length > 2 ? `${shown} · +${all.value.length - 2}` : shown
})
// What it takes, at a glance.
const steps = computed(() => {
  const s = (f.value.fix || '').trim()
  return /^1\.\s/.test(s) ? s.split(/\s(?=\d{1,2}\.\s)/).length : 1
})
const chip = computed(() => {
  if (props.group.fixable.length) return { text: props.t.canAutoFix, cls: 'bg-accent-soft text-accent' }
  if (props.group.rest.length) return { text: props.t.places(all.value.length), cls: 'bg-panel2 text-muted' }
  return { text: props.t.steps(steps.value), cls: 'bg-panel2 text-muted' }
})
</script>

<template>
  <div class="rise overflow-hidden rounded-xl bg-panel ring-1 ring-line transition-shadow hover:ring-accent/50" :style="{ animationDelay: `${Math.min(index, 14) * 28}ms` }">
    <!-- The whole header toggles; the Fix button stops the click. -->
    <div class="grid cursor-pointer grid-cols-[4px_minmax(0,1fr)_auto] items-stretch gap-x-4 select-none" @click="open = !open">
      <span class="rounded-r-sm" :class="bar[f.severity]" />
      <button class="min-w-0 py-3 text-left" :aria-expanded="open" @click.stop="open = !open">
        <span class="block text-[15.5px] leading-snug font-semibold break-words">{{ title }}</span>
        <span v-if="sub" class="mt-0.5 block truncate font-mono text-[12.5px] text-muted">{{ sub }}</span>
      </button>
      <div class="flex items-center gap-2.5 pr-3">
        <span class="hidden rounded-full px-2.5 py-1 text-[12px] font-bold whitespace-nowrap sm:inline" :class="chip.cls">{{ chip.text }}</span>
        <button v-if="group.fixable.length" class="rounded-[10px] bg-accent px-3.5 py-1.5 text-[13px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50"
          :disabled="busy" @click.stop="emit('fix', group.fixable)">{{ t.fix }}</button>
        <span class="grid h-8 w-8 place-items-center rounded-lg text-muted" aria-hidden="true">
          <svg width="14" height="14" viewBox="0 0 16 16" :class="open ? 'rotate-180' : ''" class="transition-transform"><path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>
        </span>
      </div>
    </div>

    <div v-if="open" class="grid gap-4 border-t border-line px-5 pt-4 pb-5">
      <div class="flex flex-wrap items-center gap-2">
        <SevChip :sev="f.severity" :label="t.sev[f.severity]" />
        <span class="ml-auto font-mono text-[12px] text-muted">{{ f.rule_id }}</span>
      </div>
      <p class="max-w-[76ch] text-[15px] leading-relaxed text-muted">{{ f.explain }}</p>
      <div class="grid gap-3 rounded-xl bg-panel2 px-4 py-3.5 ring-1 ring-line">
        <div class="caps">{{ t.howLabel }}</div>
        <PerPlace v-if="pp && pp.plan" :pp="pp" :t="t" />
        <div v-else-if="f.plan" class="grid gap-1.5"><CodeLine v-for="(c, k) in f.plan" :key="k" :code="c" :t="t" /></div>
        <template v-else>
          <FixSteps :text="f.fix" :t="t" :hide="pp ? pp.hide : undefined" />
          <PerPlace v-if="pp" class="border-t border-line pt-3" :pp="pp" :t="t" />
        </template>
      </div>
      <div v-if="group.rest.length && !pp">
        <div class="caps mb-1.5">{{ t.places(group.rest.length + 1) }}</div>
        <ul class="grid max-h-56 gap-1 overflow-y-auto border-l-2 border-line pl-3 font-mono text-[12.5px] text-muted">
          <li v-for="x in all" :key="x.key" class="break-all">{{ placeOf(x) }}</li>
        </ul>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <span v-if="f.needs_root" class="text-[13px] text-muted">{{ t.needsAdmin }}</span>
        <span v-else-if="f.plan" class="text-[13px] text-muted">{{ f.undoable ? t.undoable : t.noUndo }}</span>
        <button class="ml-auto rounded-[10px] border border-line px-3 py-1.5 text-[13px] font-semibold text-muted hover:bg-panel2 hover:text-fg" @click="emit('ignore', all)">{{ t.ignore }}…</button>
      </div>
    </div>
  </div>
</template>
