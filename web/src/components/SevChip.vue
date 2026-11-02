<script setup>
defineProps({ sev: String, label: String, dot: Boolean })
const cls = {
  critical: 'bg-crit-bg text-crit', high: 'bg-high-bg text-high', medium: 'bg-med-bg text-med',
  low: 'bg-low-bg text-low', info: 'bg-info-bg text-info',
}
const dotCls = { critical: 'bg-crit', high: 'bg-high', medium: 'bg-med', low: 'bg-low', info: 'bg-info' }
</script>

<template>
  <span class="inline-flex items-center gap-1.5 rounded-md px-2 py-[3px] font-mono text-[10.5px] font-semibold uppercase tracking-[.08em]" :class="cls[sev]">
    <i v-if="dot" class="h-1.5 w-1.5 rounded-full" :class="dotCls[sev]" />{{ label }}
  </span>
</template>
