<script setup>
// Renders a rule's fix text: "1. … 2. …" becomes a numbered list and
// `backticked` commands become code (on their own line with a Copy button
// when they are commands). Text stays text: nothing is ever read as HTML.
import { computed } from 'vue'
import CodeLine from './CodeLine.vue'
import { isBlock } from '../fixgroup.js'

// hide: commands that differ per place; they are listed per place below
// the steps, so here they become a short pointer.
const props = defineProps({ text: { type: String, default: '' }, t: { type: Object, required: true }, hide: { type: Set, default: () => new Set() } })

function parse(step) {
  const parts = []
  for (const p of step.split(/(`[^`]+`)/)) {
    if (!p) continue
    if (p.length > 2 && p.startsWith('`') && p.endsWith('`')) parts.push({ code: p.slice(1, -1) })
    else parts.push({ text: p })
  }
  // Separators between two block commands ("·", ",") are noise once each
  // command has its own line.
  return parts.filter((p, i) => !(p.text !== undefined && /^\s*[·,;]?\s*$/.test(p.text) && isBlock(parts[i - 1]?.code || '') && isBlock(parts[i + 1]?.code || '')))
}

const steps = computed(() => {
  const s = (props.text || '').trim()
  const items = /^1\.\s/.test(s) ? s.split(/\s(?=\d{1,2}\.\s)/).map(x => x.replace(/^\d{1,2}\.\s+/, '')) : [s]
  return items.map(parse)
})
</script>

<template>
  <ol class="grid gap-3">
    <li v-for="(parts, i) in steps" :key="i" class="grid grid-cols-[1.5rem_minmax(0,1fr)] gap-x-3 text-[14.5px] leading-relaxed">
      <span v-if="steps.length > 1" class="mt-0.5 grid h-6 w-6 place-items-center rounded-full bg-accent text-[12px] font-bold text-accent-ink">{{ i + 1 }}</span>
      <span v-else class="mt-0.5 font-bold text-accent">→</span>
      <!-- In reading order: text inline, a command breaks onto its own line. -->
      <div class="min-w-0 break-words">
        <template v-for="(p, j) in parts" :key="j">
          <template v-if="p.text !== undefined">{{ p.text }}</template>
          <code v-else-if="!isBlock(p.code)" class="mx-0.5 rounded-md bg-panel px-1.5 py-0.5 font-mono text-[13px] ring-1 ring-line">{{ p.code }}</code>
          <span v-else-if="hide.has(p.code)" class="mx-0.5 rounded-md bg-accent-soft px-1.5 py-0.5 text-[13px] font-semibold text-accent">{{ t.seeBelow }}</span>
          <CodeLine v-else class="my-1.5" :code="p.code" :t="t" />
        </template>
      </div>
    </li>
  </ol>
</template>
