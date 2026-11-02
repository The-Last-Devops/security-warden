<script setup>
import { computed } from 'vue'
// Semicircle gauge: the arc fills to the score, coloured by zone.
const props = defineProps({ score: { type: Number, default: 0 }, label: String })
const R = 80
const len = Math.PI * R
const color = computed(() => (props.score >= 80 ? 'var(--color-ok)' : props.score >= 50 ? 'var(--color-med)' : 'var(--color-crit)'))
const dash = computed(() => `${(len * Math.max(props.score, 1)) / 100} ${len}`)
</script>

<template>
  <div class="relative grid place-items-center" role="img" :aria-label="`${label}: ${score}/100`">
    <svg width="200" height="116" viewBox="0 0 200 116" aria-hidden="true">
      <path d="M20 100a80 80 0 0 1 160 0" fill="none" stroke="var(--color-line)" stroke-width="14" stroke-linecap="round" />
      <path :key="score" class="draw" d="M20 100a80 80 0 0 1 160 0" fill="none" :stroke="color" stroke-width="14" stroke-linecap="round"
        :stroke-dasharray="dash" :style="{ '--len': `${len}` }" />
    </svg>
    <div class="absolute bottom-0 text-center leading-none">
      <div class="num text-[46px] font-extrabold tracking-tight" :style="{ color }">{{ score }}</div>
      <div class="mt-1.5 text-[13px] text-muted">{{ label }} / 100</div>
    </div>
  </div>
</template>
