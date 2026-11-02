<script setup>
defineProps({ sev: String, label: String, dot: Boolean })
const cls = {
  critical: 'bg-crit text-white', high: 'bg-high text-white', medium: 'bg-med-bg text-med ring-1 ring-med/30',
  low: 'bg-low-bg text-low ring-1 ring-low/30', info: 'bg-info-bg text-info',
}
const dotCls = { critical: 'bg-crit', high: 'bg-high', medium: 'bg-med', low: 'bg-low', info: 'bg-info' }
</script>

<template>
  <span class="inline-flex items-center gap-1.5 rounded-md px-2 py-[3px] font-mono text-[11.5px] font-bold uppercase tracking-[.06em]" :class="cls[sev]">
    {{ label }}
  </span>
</template>
