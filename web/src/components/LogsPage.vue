<script setup>
// The scan log as a full page (☰ menu, #logs): one event per line, colored
// by level, newest first, with a filter. Read-only.
import { computed, onMounted, ref } from 'vue'
import { api } from '../api.js'

// inline: a sub-page of Settings (no back button, title or close).
const props = defineProps({ t: { type: Object, required: true }, inline: Boolean })
const emit = defineEmits(['close', 'bug'])
const log = ref(null)
const err = ref('')
const copied = ref(false)
const level = ref('all')

async function load() {
  err.value = ''
  try { log.value = await api.logs() } catch (e) { err.value = e.message }
}
onMounted(load)

// "2026-11-04 10:14:48 WARN  [git_history] slow: 5.7s"
const lines = computed(() => (log.value?.text || '').split('\n').filter(Boolean).reverse().map(raw => {
  const m = raw.match(/^(\S+ \S+) (INFO|WARN|ERROR)\s+\[([^\]]+)\] (.*)$/)
  // A line in another format is shown as it is, with no made-up level.
  return m ? { raw, time: m[1], level: m[2], src: m[3], msg: m[4] } : { raw, level: '' }
}))
const counts = computed(() => {
  const c = { all: lines.value.length, WARN: 0, ERROR: 0 }
  for (const l of lines.value) if (l.level in c) c[l.level]++
  return c
})
const shown = computed(() => (level.value === 'all' ? lines.value : lines.value.filter(l => l.level === level.value)))
const filters = computed(() => [['all', props.t.logAll], ['WARN', props.t.logWarn], ['ERROR', props.t.logError]])
const tone = { INFO: 'bg-panel text-muted', WARN: 'bg-med-bg text-med', ERROR: 'bg-crit-bg text-crit' }

async function copy() {
  try {
    await navigator.clipboard.writeText(log.value.text)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  } catch {}
}
</script>

<template>
  <div class="grid gap-5" :class="inline ? 'min-w-0' : 'mx-auto max-w-[1080px] px-4 py-6 sm:px-6'">
    <div class="flex flex-wrap items-center gap-3">
      <button v-if="!inline" class="flex items-center gap-2 rounded-xl bg-panel2 px-4 py-2.5 text-[15px] font-semibold ring-1 ring-line hover:bg-accent-soft hover:text-accent" @click="emit('close')">
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" /></svg>{{ t.backToResults }}
      </button>
      <h1 v-if="!inline" class="text-[26px] font-extrabold">{{ t.scanLog }}</h1>
      <div class="ml-auto flex gap-2">
        <button class="rounded-xl px-4 py-2 text-[14.5px] font-semibold text-muted ring-1 ring-line hover:text-fg" @click="load">{{ t.refresh }}</button>
        <button class="rounded-xl px-4 py-2 text-[14.5px] font-semibold text-crit ring-1 ring-line hover:bg-crit-bg" @click="emit('bug')">{{ t.reportBug }}</button>
        <button v-if="log?.text" class="rounded-xl bg-accent px-4 py-2 text-[14.5px] font-semibold text-accent-ink hover:brightness-110" @click="copy">{{ copied ? t.copied : t.copy }}</button>
        <button v-if="!inline" class="grid h-11 w-11 place-items-center rounded-xl text-[18px] text-muted ring-1 ring-line hover:bg-panel2 hover:text-fg" :aria-label="t.close" :title="t.close + ' (Esc)'" @click="emit('close')">✕</button>
      </div>
    </div>
    <p class="text-[15px] text-muted">{{ t.scanLogHelp }}</p>

    <p v-if="err" class="rounded-xl bg-crit-bg px-4 py-3 text-[15px] text-crit">{{ t.error }}: {{ err }}</p>
    <p v-else-if="!log" class="py-10 text-center text-muted">{{ t.loading }}</p>
    <p v-else-if="!lines.length" class="panel py-12 text-center text-[15px] text-muted">{{ t.scanLogEmpty }}</p>
    <template v-else>
      <div class="flex flex-wrap gap-2" role="tablist">
        <button v-for="f in filters" :key="f[0]" role="tab" :aria-selected="level === f[0]"
          class="rounded-full px-4 py-1.5 text-[14px] font-semibold ring-1" :class="level === f[0] ? 'bg-accent text-accent-ink ring-accent' : 'text-muted ring-line hover:text-fg'"
          @click="level = f[0]">{{ f[1] }} · <span class="num">{{ counts[f[0]] }}</span></button>
      </div>
      <div class="panel overflow-hidden">
        <p v-if="!shown.length" class="py-10 text-center text-[15px] text-muted">{{ t.logNone }}</p>
        <div v-for="(l, i) in shown" :key="i" class="border-t border-line first:border-t-0">
        <p v-if="!l.level" class="px-4 py-2.5 font-mono text-[13px] break-words text-muted">{{ l.raw }}</p>
        <div v-else class="grid grid-cols-[auto_auto_1fr] items-baseline gap-x-3 px-4 py-2.5 max-sm:grid-cols-[auto_1fr]">
          <span class="num text-[13px] text-muted max-sm:col-span-2">{{ l.time }}</span>
          <span class="w-[58px] rounded-md px-1.5 py-0.5 text-center text-[11.5px] font-bold tracking-wide" :class="tone[l.level]">{{ l.level }}</span>
          <span class="min-w-0 text-[14.5px] break-words"><b v-if="l.src" class="font-semibold">{{ l.src }}</b> <span :class="l.msg.startsWith('command:') ? 'font-mono text-[13px] text-muted' : ''">{{ l.msg }}</span></span>
        </div>
        </div>
      </div>
      <p v-if="log.path" class="font-mono text-[13px] break-all text-muted">{{ log.path }}</p>
    </template>
  </div>
</template>
