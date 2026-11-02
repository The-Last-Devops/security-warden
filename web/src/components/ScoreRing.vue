<script setup>
import { computed } from 'vue'
const props = defineProps({ score: { type: Number, default: 0 }, size: { type: Number, default: 64 } })
const r = 27
const circ = 2 * Math.PI * r
const dash = computed(() => `${(circ * props.score) / 100} ${circ}`)
const tone = computed(() => (props.score >= 80 ? 'text-ok' : props.score >= 50 ? 'text-med' : 'text-high'))
</script>

<template>
  <svg :width="size" :height="size" viewBox="0 0 64 64" role="img" :aria-label="`${score}/100`" class="shrink-0">
    <circle cx="32" cy="32" :r="r" fill="none" stroke="currentColor" class="text-line" stroke-width="7" />
    <circle cx="32" cy="32" :r="r" fill="none" stroke="currentColor" :class="tone" stroke-width="7"
      stroke-linecap="round" :stroke-dasharray="dash" transform="rotate(-90 32 32)" />
    <text x="32" y="38" text-anchor="middle" font-size="18" font-weight="700" fill="currentColor">{{ score }}</text>
  </svg>
</template>
