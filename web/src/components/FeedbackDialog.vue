<script setup>
// A GitHub issue draft: a wrong finding (key), an idea for a new check, or
// a bug report (bug), which carries the newest lines of the scan log.
// The server takes identifying details out and builds the link; this page
// only shows the text and opens the link in a new tab. Nothing is sent.
import { onMounted, ref } from 'vue'
import { api } from '../api.js'

const props = defineProps({ t: { type: Object, required: true }, findingKey: { type: String, default: '' }, bug: Boolean })
const emit = defineEmits(['close'])
const idea = ref('')
const withLog = ref(true)
const draft = ref(null)
const err = ref('')
const busy = ref(false)

async function load(fn) {
  busy.value = true; err.value = ''
  try { draft.value = await fn() } catch (e) { err.value = e.message } finally { busy.value = false }
}
onMounted(() => { if (props.findingKey) load(() => api.feedback(props.findingKey)) })
const preview = () => idea.value.trim() && load(() => (props.bug ? api.feedbackBug(idea.value, withLog.value) : api.feedbackIdea(idea.value)))
</script>

<template>
  <div class="fixed inset-0 z-40 grid place-items-center bg-black/55 p-4 backdrop-blur-sm" @click.self="emit('close')" @keydown.esc="emit('close')">
    <section class="panel rise grid max-h-[88vh] w-full max-w-xl min-w-0 gap-4 overflow-y-auto p-6 shadow-2xl" role="dialog" aria-modal="true" aria-labelledby="fb-title">
      <div class="flex items-center gap-3">
        <h2 id="fb-title" class="text-[18px] font-bold">{{ findingKey ? t.fbTitleFp : bug ? t.fbTitleBug : t.fbTitleIdea }}</h2>
        <button class="ml-auto grid h-9 w-9 shrink-0 place-items-center rounded-lg text-muted ring-1 ring-line hover:text-fg" :aria-label="t.close" @click="emit('close')">✕</button>
      </div>

      <template v-if="!findingKey && !draft">
        <label class="grid gap-2">
          <span class="text-[14px] text-muted">{{ bug ? t.fbBugHelp : t.fbIdeaHelp }}</span>
          <textarea v-model="idea" rows="5" maxlength="4000" :placeholder="bug ? t.fbBugPlaceholder : t.fbIdeaPlaceholder"
            class="w-full min-w-0 rounded-[10px] bg-panel2 px-3.5 py-2.5 text-[15px] ring-1 ring-line outline-none placeholder:text-muted focus:ring-accent" />
        </label>
        <label v-if="bug" class="flex cursor-pointer items-start gap-3 rounded-xl bg-panel2 px-4 py-3 ring-1 ring-line">
          <input v-model="withLog" type="checkbox" class="mt-1 h-4 w-4 accent-[var(--color-accent)]" />
          <span><b class="block text-[15px] font-semibold">{{ t.fbAttachLog }}</b><small class="text-[13.5px] text-muted">{{ t.fbAttachLogHelp }}</small></span>
        </label>
      </template>
      <a v-if="bug" href="/api/logs?download=1" download class="justify-self-start text-[14px] font-semibold text-accent hover:underline">⤓ {{ t.fbDownloadLog }}</a>

      <p v-if="err" class="rounded-xl bg-crit-bg px-4 py-3 text-[14px] text-crit">{{ t.error }}: {{ err }}</p>
      <p v-else-if="busy" class="py-6 text-center text-muted">{{ t.loading }}</p>

      <template v-if="draft">
        <div class="grid gap-2">
          <span class="caps">{{ t.fbPreview }}</span>
          <pre class="max-h-[42vh] overflow-auto rounded-xl bg-panel2 px-4 py-3 font-mono text-[12.5px] leading-relaxed break-words whitespace-pre-wrap ring-1 ring-line">{{ draft.preview }}</pre>
          <p v-if="draft.shortened" class="text-[13px] text-med">{{ t.fbShortened }}</p>
        </div>
        <p class="text-[13.5px] text-muted">{{ t.fbPrivacy }}</p>
      </template>

      <div class="flex flex-wrap justify-end gap-2">
        <button v-if="draft && !findingKey" class="mr-auto rounded-xl px-3 py-2.5 text-[14px] font-semibold text-muted hover:text-fg" @click="draft = null">{{ t.fbEdit }}</button>
        <button class="rounded-xl px-4 py-2.5 text-[14px] font-semibold text-muted hover:text-fg" @click="emit('close')">{{ t.cancel }}</button>
        <button v-if="!draft && !findingKey" class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110 disabled:opacity-50"
          :disabled="busy || !idea.trim()" @click="preview">{{ t.fbPreviewBtn }}</button>
        <a v-if="draft" :href="draft.url" target="_blank" rel="noopener noreferrer"
          class="rounded-xl bg-accent px-4 py-2.5 text-[14px] font-semibold text-accent-ink hover:brightness-110">{{ t.fbOpen }} ↗</a>
      </div>
    </section>
  </div>
</template>
