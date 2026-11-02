<script setup>
defineProps({ sev: String, label: String })
const cls = {
  critical: 'bg-crit-bg text-crit', high: 'bg-high-bg text-high', medium: 'bg-med-bg text-med',
  low: 'bg-low-bg text-low', info: 'bg-info-bg text-info',
}
</script>

<template>
  <span class="inline-block rounded-full px-2 py-0.5 text-[11.5px] font-semibold uppercase tracking-wide" :class="cls[sev]">{{ label }}</span>
</template>
