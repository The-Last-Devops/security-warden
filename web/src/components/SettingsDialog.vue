<script setup>
// Settings as a roomy dialog in four groups: display, sign-in, updates and
// other. Every row has a name, one line of help and its control on the right.
import Segmented from './Segmented.vue'
import CodeLine from './CodeLine.vue'

defineProps({
  t: { type: Object, required: true },
  themeOptions: { type: Array, required: true },
  langOptions: { type: Array, required: true },
  pk: { type: Object, required: true },
  canPasskey: Boolean,
  upd: { type: Object, default: null },
  busy: Boolean,
  checkedAt: { type: String, default: '' },
})
const theme = defineModel('theme')
const lang = defineModel('lang')
const emit = defineEmits(['close', 'add-passkey', 'clear-passkeys', 'toggle-auto', 'undo', 'logout'])
</script>

<template>
  <div class="fixed inset-0 z-40 grid place-items-start overflow-y-auto bg-black/50 px-4 py-[6vh] backdrop-blur-sm" @click.self="emit('close')" @keydown.esc="emit('close')">
    <section class="panel rise mx-auto grid w-full max-w-[560px] gap-4 p-5 shadow-2xl sm:p-6" role="dialog" aria-modal="true" aria-labelledby="settings-title">
      <div class="flex items-center">
        <h2 id="settings-title" class="text-[19px] font-extrabold">{{ t.settings }}</h2>
        <button class="ml-auto grid h-9 w-9 place-items-center rounded-lg text-muted ring-1 ring-line hover:text-fg" :aria-label="t.close" @click="emit('close')">✕</button>
      </div>

      <div class="srow-group">
        <h3>{{ t.groupDisplay }}</h3>
        <div class="srow"><div><b>{{ t.theme }}</b><small>{{ t.themeHelp }}</small></div><Segmented v-model="theme" :options="themeOptions" :label="t.theme" /></div>
        <div class="srow"><div><b>{{ t.language }}</b><small>{{ t.languageHelp }}</small></div><Segmented v-model="lang" :options="langOptions" :label="t.language" /></div>
      </div>

      <div class="srow-group">
        <h3>{{ t.groupSignIn }}</h3>
        <div class="srow">
          <div><b>{{ t.passkeysSection }}</b><small>{{ t.passkeys(pk.count) }}</small></div>
          <button v-if="canPasskey" class="rounded-[10px] bg-accent px-3.5 py-2 text-[13.5px] font-semibold text-accent-ink hover:brightness-110" @click="emit('add-passkey')">{{ t.addPasskey }}</button>
        </div>
        <div class="srow">
          <div><b>{{ t.session }}</b><small>{{ t.sessionHelp }}</small></div>
          <button class="rounded-[10px] bg-panel px-3.5 py-2 text-[13.5px] font-semibold ring-1 ring-line hover:text-accent" @click="emit('logout')">{{ t.signOut }}</button>
        </div>
      </div>

      <div v-if="upd" class="srow-group">
        <h3>{{ t.updates }}</h3>
        <div class="srow">
          <div>
            <b>{{ t.version('') }} <span class="font-mono text-[13px] font-medium">{{ upd.current }}</span>
              <span class="ml-1 rounded-full px-2 py-0.5 align-[1px] text-[11px] font-bold" :class="upd.available ? 'bg-crit-bg text-crit' : 'bg-ok-bg text-ok'">{{ upd.available ? t.newVersionShort(upd.latest) : t.upToDate }}</span></b>
            <small v-if="checkedAt">{{ t.checkedAt(checkedAt) }}</small>
          </div>
        </div>
        <div class="srow">
          <div><b>{{ t.autoUpdate }}</b><small>{{ upd.method === 'brew' ? t.autoUpdateHelpBrew : t.updateHowManual }}</small></div>
          <button type="button" role="switch" :aria-checked="upd.auto" :aria-label="t.autoUpdate" class="relative h-6 w-11 shrink-0 rounded-full transition-colors" :class="upd.auto ? 'bg-accent' : 'bg-line'" @click="emit('toggle-auto')">
            <span class="absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all" :class="upd.auto ? 'left-[22px]' : 'left-0.5'" />
          </button>
        </div>
        <div v-if="upd.method === 'brew'" class="grid gap-1.5 px-4 pt-1 pb-4">
          <small class="text-[13px] text-muted">{{ t.updateCmds }}</small>
          <CodeLine code="security-warden update" :t="t" />
          <CodeLine code="brew upgrade security-warden" :t="t" />
        </div>
      </div>

      <div class="srow-group">
        <h3>{{ t.groupOther }}</h3>
        <div class="srow">
          <div><b>{{ t.undo }}</b><small>{{ t.undoHelp }}</small></div>
          <button class="rounded-[10px] bg-panel px-3.5 py-2 text-[13.5px] font-semibold ring-1 ring-line hover:text-accent disabled:opacity-50" :disabled="busy" @click="emit('undo')">{{ t.undoShort }}</button>
        </div>
        <div v-if="pk.count" class="srow">
          <div><b class="text-crit">{{ t.removePasskeys }}</b><small>{{ t.removePasskeysHelp }}</small></div>
          <button class="rounded-[10px] px-3.5 py-2 text-[13.5px] font-semibold text-crit ring-1 ring-line hover:bg-crit-bg" @click="emit('clear-passkeys')">{{ t.remove }}</button>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.srow-group { display: grid; overflow: hidden; border-radius: 14px; background: var(--color-panel2); box-shadow: inset 0 0 0 1px var(--color-line) }
.srow-group h3 { margin: 0; padding: 12px 16px 2px; font-size: 11.5px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; color: var(--color-muted) }
.srow { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 14px; padding: 12px 16px; border-top: 1px solid var(--color-line) }
.srow-group h3 + .srow { border-top: 0 }
.srow > div:first-child { flex: 1 1 14rem; min-width: 0 }
.srow b { display: block; font-size: 15px; font-weight: 600 }
.srow small { display: block; margin-top: 2px; font-size: 13px; color: var(--color-muted) }
</style>
