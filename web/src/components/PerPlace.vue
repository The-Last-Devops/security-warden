<script setup>
// The commands that differ per place: each place, its commands, and Copy all.
import { computed, ref } from 'vue'
import CodeLine from './CodeLine.vue'

const props = defineProps({ pp: { type: Object, required: true }, t: { type: Object, required: true } })
const done = ref(false)
const all = computed(() => props.pp.places.flatMap(p => p.cmds).join('\n'))

async function copyAll() {
  try {
    await navigator.clipboard.writeText(all.value)
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: all.value })
    document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove()
  }
  done.value = true
  setTimeout(() => { done.value = false }, 1500)
}
</script>

<template>
  <div class="grid gap-2">
    <div class="flex items-center gap-2">
      <span class="caps">{{ t.perPlace(pp.places.length) }}</span>
      <button class="ml-auto rounded-md px-2.5 py-1 text-[12.5px] font-semibold ring-1" :class="done ? 'bg-ok-bg text-ok ring-transparent' : 'bg-panel text-muted ring-line hover:text-accent'" @click.stop="copyAll">
        {{ done ? t.copied : t.copyAll(pp.places.flatMap(p => p.cmds).length) }}
      </button>
    </div>
    <div class="grid max-h-[26rem] gap-2.5 overflow-y-auto pr-1">
      <div v-for="(p, i) in pp.places" :key="i" class="grid gap-1">
        <span class="truncate font-mono text-[12px] text-muted">{{ p.place }}</span>
        <CodeLine v-for="(c, k) in p.cmds" :key="k" :code="c" :t="t" />
      </div>
    </div>
  </div>
</template>
