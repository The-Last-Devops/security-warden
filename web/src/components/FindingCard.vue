<script setup>
import { ref } from 'vue'
import SevChip from './SevChip.vue'

const props = defineProps({ group: Object, t: Object, busy: Boolean, index: Number })
const emit = defineEmits(['fix'])
const open = ref(false)
const rail = { critical: 'rail-critical', high: 'bg-high', medium: 'bg-med', low: 'bg-low', info: 'bg-info' }
</script>

<template>
  <article class="rise group relative grid min-w-0 gap-2.5 overflow-hidden rounded-xl border border-line bg-panel py-4 pr-4 pl-6 transition-shadow hover:shadow-[0_6px_24px_-12px_rgba(0,0,0,.25)]"
    :style="{ animationDelay: `${Math.min(index, 12) * 35}ms` }">
    <span class="absolute inset-y-0 left-0 w-[5px]" :class="rail[group.first.severity]" aria-hidden="true" />

    <header class="flex flex-wrap items-center gap-x-3 gap-y-1.5">
      <SevChip :sev="group.first.severity" :label="t.sev[group.first.severity]" />
      <span v-if="group.rest.length" class="num rounded-md bg-side px-1.5 py-[3px] text-[10.5px] font-semibold text-muted">×{{ group.rest.length + 1 }}</span>
      <span class="ml-auto font-mono text-[10.5px] text-muted">{{ group.first.rule_id }}</span>
    </header>

    <h3 class="font-display text-[16.5px] leading-snug font-semibold break-words">{{ group.first.title }}</h3>
    <p class="max-w-[74ch] text-[13.5px] leading-relaxed text-muted break-words">{{ group.first.explain }}</p>

    <div v-if="group.first.plan" class="overflow-x-auto rounded-lg border border-line bg-side px-3 py-2 font-mono text-[12.5px] whitespace-pre"><span class="text-muted select-none">$ </span>{{ group.first.plan.join('\n$ ') }}</div>
    <p v-else class="flex gap-2 text-[13.5px] leading-relaxed break-words"><span class="font-mono text-accent">→</span><span>{{ group.first.fix }}</span></p>

    <details v-if="group.rest.length" class="text-[12.5px] text-muted" :open="open" @toggle="open = $event.target.open">
      <summary class="w-fit font-semibold text-fg/80 hover:text-fg">{{ t.sameIssue(group.rest.length) }}</summary>
      <ul class="mt-1.5 grid gap-1 border-l border-line pl-3">
        <li v-for="f in group.rest" :key="f.key" class="break-words">{{ f.title }}</li>
      </ul>
    </details>

    <footer v-if="group.fixable.length || group.first.needs_root" class="flex flex-wrap items-center gap-3 pt-0.5">
      <button v-if="group.fixable.length" :disabled="busy"
        class="rounded-lg bg-accent px-3.5 py-1.5 text-[12.5px] font-semibold text-accent-ink transition hover:brightness-110 disabled:opacity-50"
        @click="emit('fix', group.fixable)">
        {{ group.fixable.length > 1 ? t.fixN(group.fixable.length) : t.fixNow }}
      </button>
      <span v-if="group.first.needs_root" class="text-[12px] text-muted">{{ t.needsAdmin }}</span>
      <span v-else-if="group.first.plan" class="text-[12px] text-muted">{{ group.first.undoable ? t.undoable : t.noUndo }}</span>
    </footer>
  </article>
</template>
