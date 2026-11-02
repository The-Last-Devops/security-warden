<script setup>
defineProps({ sev: String, label: String })
const cls = {
  critical: 'bg-crit-bg text-crit', high: 'bg-high-bg text-high', medium: 'bg-med-bg text-med',
  low: 'bg-low-bg text-low', info: 'bg-info-bg text-info',
}
</script>

<template>
  <span class="inline-block shrink-0 rounded-full px-2.5 py-1 text-[11.5px] leading-none font-bold tracking-[.06em] uppercase" :class="cls[sev]">{{ label }}</span>
</template>
