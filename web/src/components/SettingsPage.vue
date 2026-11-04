<script setup>
// Settings as a full page (☰ menu): one sub-page per group, display,
// sign-in, updates and other, picked from a list on the left (tabs on a
// phone) and kept in the hash (#settings/display) so Back works. Every row
// has a name, a line of help and its control.
import { computed } from 'vue'
import Segmented from './Segmented.vue'
import CodeLine from './CodeLine.vue'
import RulesPage from './RulesPage.vue'
import LogsPage from './LogsPage.vue'
import { inApp } from '../passkey.js'

const props = defineProps({
  tab: { type: String, default: '' },
  uiLang: { type: String, default: 'en' },
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
const experimental = defineModel('experimental', { type: Boolean, default: false })
const emit = defineEmits(['close', 'add-passkey', 'clear-passkeys', 'toggle-auto', 'toggle-auto-app', 'undo', 'logout', 'bug'])
const tabs = computed(() => [['display', props.t.groupDisplay], ['signin', props.t.groupSignIn], ...(props.upd ? [['updates', props.t.updates]] : []), ['other', props.t.groupOther], ['logs', props.t.scanLog], ['rules', props.t.rulesSources]])
const cur = computed(() => (tabs.value.some(x => x[0] === props.tab) ? props.tab : 'display'))
const title = computed(() => tabs.value.find(x => x[0] === cur.value)[1])
const open = id => { location.hash = 'settings/' + id }
</script>

<template>
  <div class="mx-auto grid max-w-[1080px] gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[220px_1fr]">
    <div class="lg:col-span-2 flex flex-wrap items-center gap-3">
      <button class="flex items-center gap-2 rounded-xl bg-panel2 px-4 py-2.5 text-[15px] font-semibold ring-1 ring-line hover:bg-accent-soft hover:text-accent" @click="emit('close')">
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true"><path d="M15 5l-7 7 7 7" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" /></svg>{{ t.backToResults }}
      </button>
      <h1 class="text-[26px] font-extrabold">{{ t.settings }}</h1>
      <span class="ml-auto"></span>
      <button class="grid h-11 w-11 place-items-center rounded-xl text-[18px] text-muted ring-1 ring-line hover:bg-panel2 hover:text-fg" :aria-label="t.close" :title="t.close + ' (Esc)'" @click="emit('close')">✕</button>
    </div>

    <nav class="flex content-start gap-1 overflow-x-auto lg:sticky lg:top-6 lg:grid" :aria-label="t.settings">
      <button v-for="s in tabs" :key="s[0]" :aria-current="cur === s[0] ? 'page' : undefined"
        class="shrink-0 rounded-lg px-3.5 py-2.5 text-left text-[15.5px] font-semibold" :class="cur === s[0] ? 'bg-accent-soft text-accent' : 'text-muted hover:bg-panel2 hover:text-fg'" @click="open(s[0])">{{ s[1] }}</button>
      <button class="shrink-0 rounded-lg px-3.5 py-2.5 text-left text-[15.5px] font-semibold text-crit hover:bg-crit-bg lg:mt-2 lg:border-t lg:border-line lg:rounded-t-none" @click="emit('bug')">{{ t.reportBug }}</button>
    </nav>

    <div class="grid min-w-0 content-start gap-4">
      <h2 class="text-[21px] font-bold">{{ title }}</h2>
      <section v-if="cur === 'display'" class="srow-group">
        <div class="srow"><div><b>{{ t.theme }}</b><small>{{ t.themeHelp }}</small></div><Segmented v-model="theme" :options="themeOptions" :label="t.theme" /></div>
        <div class="srow"><div><b>{{ t.language }}</b><small>{{ t.languageHelp }}</small></div><select v-model="lang" :aria-label="t.language" class="h-11 min-w-44 cursor-pointer rounded-xl border border-line bg-panel px-3.5 text-[15px] font-semibold focus:outline-none focus:ring-2 focus:ring-accent">
            <option value="auto">{{ t.auto }}</option>
            <option value="vi">Tiếng Việt</option>
            <option value="en">English</option>
          </select></div>
      </section>

      <section v-if="cur === 'signin'" class="srow-group">
        <div class="srow">
          <div><b>{{ t.passkeysSection }}</b><small>{{ inApp() ? t.passkeysApp : t.passkeys(pk.count) }}</small></div>
          <button v-if="canPasskey" class="btn bg-accent text-accent-ink hover:brightness-110" @click="emit('add-passkey')">{{ t.addPasskey }}</button>
        </div>
        <div class="srow">
          <div><b>{{ t.session }}</b><small>{{ t.sessionHelp }}</small></div>
          <button class="btn bg-panel ring-1 ring-line hover:text-accent" @click="emit('logout')">{{ t.signOut }}</button>
        </div>
        <div v-if="pk.count" class="srow">
          <div><b class="text-crit">{{ t.removePasskeys }}</b><small>{{ t.removePasskeysHelp }}</small></div>
          <button class="btn text-crit ring-1 ring-line hover:bg-crit-bg" @click="emit('clear-passkeys')">{{ t.remove }}</button>
        </div>
      </section>

      <section v-if="cur === 'updates' && upd" class="srow-group">
        <div class="srow">
          <div>
            <b>{{ t.version('') }} <span class="font-mono text-[14px] font-medium">{{ upd.current }}</span>
              <span class="ml-1 rounded-full px-2 py-0.5 align-[1px] text-[12px] font-bold" :class="upd.available ? 'bg-crit-bg text-crit' : 'bg-ok-bg text-ok'">{{ upd.available ? t.newVersionShort(upd.latest) : t.upToDate }}</span></b>
            <small v-if="checkedAt">{{ t.checkedAt(checkedAt) }}</small>
          </div>
        </div>
        <div class="srow">
          <div><b>{{ t.autoUpdate }}</b><small>{{ upd.method === 'brew' ? t.autoUpdateHelpBrew : t.updateHowManual }}</small></div>
          <button type="button" role="switch" :aria-checked="upd.auto" :aria-label="t.autoUpdate" class="relative h-7 w-12 shrink-0 rounded-full transition-colors" :class="upd.auto ? 'bg-accent' : 'bg-line'" @click="emit('toggle-auto')">
            <span class="absolute top-0.5 h-6 w-6 rounded-full bg-white shadow transition-all" :class="upd.auto ? 'left-[22px]' : 'left-0.5'" />
          </button>
        </div>
        <div v-if="upd.mac && upd.method === 'brew'" class="srow">
          <div><b>{{ t.autoApp }}</b><small>{{ upd.app_installed ? t.autoAppHelpInstalled : t.autoAppHelp }}</small></div>
          <button type="button" role="switch" :aria-checked="upd.auto_app" :aria-label="t.autoApp" class="relative h-7 w-12 shrink-0 rounded-full transition-colors" :class="upd.auto_app ? 'bg-accent' : 'bg-line'" @click="emit('toggle-auto-app')">
            <span class="absolute top-0.5 h-6 w-6 rounded-full bg-white shadow transition-all" :class="upd.auto_app ? 'left-[22px]' : 'left-0.5'" />
          </button>
        </div>
        <div v-if="upd.method === 'brew'" class="grid gap-2 px-5 pt-1 pb-5">
          <small class="text-[14px] text-muted">{{ t.updateCmds }}</small>
          <CodeLine code="security-warden update" :t="t" />
          <CodeLine code="brew upgrade security-warden" :t="t" />
        </div>
      </section>

      <RulesPage v-if="cur === 'rules'" inline :t="t" :lang="uiLang" />
      <LogsPage v-if="cur === 'logs'" inline :t="t" @bug="emit('bug')" />
      <section v-if="cur === 'other'" class="srow-group">
        <div class="srow">
          <div><b>{{ t.experimental }}</b><small>{{ t.experimentalHelp }}</small></div>
          <button type="button" role="switch" :aria-checked="experimental" :aria-label="t.experimental" class="relative h-7 w-12 shrink-0 rounded-full transition-colors" :class="experimental ? 'bg-accent' : 'bg-line'" @click="experimental = !experimental">
            <span class="absolute top-0.5 h-6 w-6 rounded-full bg-white shadow transition-all" :class="experimental ? 'left-[22px]' : 'left-0.5'" />
          </button>
        </div>
        <div class="srow">
          <div><b>{{ t.undo }}</b><small>{{ t.undoHelp }}</small></div>
          <button class="btn bg-panel ring-1 ring-line hover:text-accent disabled:opacity-50" :disabled="busy" @click="emit('undo')">{{ t.undoShort }}</button>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.srow-group { display: grid; overflow: hidden; border-radius: 16px; background: var(--color-panel2); box-shadow: inset 0 0 0 1px var(--color-line) }
.srow { display: flex; flex-wrap: wrap; align-items: center; gap: 12px 18px; padding: 18px 20px; border-top: 1px solid var(--color-line) }
.srow:first-child { border-top: 0 }
.srow > div:first-child { flex: 1 1 16rem; min-width: 0 }
.srow b { display: block; font-size: 17px; font-weight: 600 }
.srow small { display: block; margin-top: 3px; font-size: 14.5px; line-height: 1.45; color: var(--color-muted) }
.btn { border-radius: 11px; padding: 9px 16px; font-size: 14.5px; font-weight: 600 }
</style>
