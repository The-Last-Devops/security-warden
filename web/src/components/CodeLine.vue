<script setup>
// One command on its own line with a Copy button.
import { ref } from 'vue'

const props = defineProps({ code: { type: String, required: true }, t: { type: Object, required: true } })
const done = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.code)
  } catch {
    const ta = Object.assign(document.createElement('textarea'), { value: props.code })
    document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove()
  }
  done.value = true
  setTimeout(() => { done.value = false }, 1500)
}
</script>

<template>
  <div class="flex min-w-0 items-center gap-2 rounded-lg bg-page/70 py-1.5 pr-1.5 pl-3 ring-1 ring-line">
    <code class="min-w-0 flex-1 overflow-x-auto font-mono text-[13px] whitespace-pre"><span class="text-muted select-none">$ </span>{{ code }}</code>
    <button class="shrink-0 rounded-md px-2.5 py-1 text-[12.5px] font-semibold ring-1" :class="done ? 'bg-ok-bg text-ok ring-transparent' : 'bg-panel2 text-muted ring-line hover:text-accent'"
      @click.stop="copy">{{ done ? t.copied : t.copy }}</button>
  </div>
</template>
