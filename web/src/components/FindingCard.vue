<script setup>
import { ref } from 'vue'
import SevChip from './SevChip.vue'

const props = defineProps({ group: Object, t: Object, busy: Boolean })
const emit = defineEmits(['fix'])
const open = ref(false)
const border = {
  critical: 'border-l-crit', high: 'border-l-high', medium: 'border-l-med', low: 'border-l-low', info: 'border-l-info',
}
</script>

<template>
  <article class="grid min-w-0 gap-2 rounded-xl border border-l-4 border-line bg-panel p-4" :class="border[group.first.severity]">
    <div class="flex flex-wrap items-baseline gap-2.5">
      <SevChip :sev="group.first.severity" :label="t.sev[group.first.severity]" />
      <h3 class="min-w-[12rem] flex-1 text-[14.5px] font-semibold break-words">{{ group.first.title }}</h3>
    </div>
    <p class="max-w-[72ch] text-[13px] text-muted break-words">{{ group.first.explain }}</p>
    <div v-if="group.first.plan" class="overflow-x-auto rounded-md bg-side px-2.5 py-1.5 font-mono text-[12.5px] whitespace-pre">{{ group.first.plan.join('\n') }}</div>
    <p v-else class="text-[13px]"><span class="text-ok">→</span> {{ group.first.fix }}</p>

    <div v-if="group.rest.length" class="text-[12.5px] text-muted">
      {{ t.sameIssue(group.rest.length) }}
      <ul class="mt-1 grid gap-0.5">
        <li v-for="f in (open ? group.rest : group.rest.slice(0, 4))" :key="f.key" class="break-words">• {{ f.title }}</li>
      </ul>
      <button v-if="group.rest.length > 4" class="mt-1 font-semibold text-accent" @click="open = !open">
        {{ open ? t.showLess : t.showAll }}
      </button>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <button v-if="group.fixable.length" :disabled="busy"
        class="rounded-lg bg-accent px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50"
        @click="emit('fix', group.fixable)">
        {{ group.fixable.length > 1 ? `${t.fix} (${group.fixable.length})` : t.fixNow }}
      </button>
      <span v-if="group.first.needs_root" class="text-xs text-muted">{{ t.needsAdmin }}</span>
      <span v-else-if="group.first.plan" class="text-xs text-muted">{{ group.first.undoable ? t.undoable : t.noUndo }}</span>
      <span class="ml-auto font-mono text-[11px] text-muted">{{ group.first.rule_id }}</span>
    </div>
  </article>
</template>
