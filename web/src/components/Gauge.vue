<script setup>
import { computed } from 'vue'
// The score as an instrument: twenty ticks that fill by zone, plus the number.
const props = defineProps({ score: { type: Number, default: 0 }, label: String })
const filled = computed(() => Math.round(props.score / 5))
const zone = i => (i < 10 ? 'bg-high' : i < 16 ? 'bg-med' : 'bg-ok')
const faint = i => (i < 10 ? 'bg-high/20' : i < 16 ? 'bg-med/25' : 'bg-ok/25')
const tone = computed(() => (props.score >= 80 ? 'text-ok' : props.score >= 50 ? 'text-med' : 'text-high'))
</script>

<template>
  <div class="flex items-end gap-4" role="img" :aria-label="`${label} ${score}/100`">
    <div class="leading-none">
      <div class="eyebrow mb-2">{{ label }}</div>
      <div class="font-display text-[64px] font-extrabold tracking-tight num" :class="tone">{{ score }}<span class="text-[22px] font-semibold text-muted">/100</span></div>
    </div>
    <div class="mb-2 flex h-10 items-end gap-[3px]" aria-hidden="true">
      <span v-for="i in 20" :key="i" class="tick w-[7px] rounded-[2px]"
        :class="[i - 1 < filled ? zone(i - 1) : faint(i - 1), i % 5 === 0 ? 'h-10' : 'h-7']"
        :style="{ animationDelay: `${i * 18}ms` }" />
    </div>
  </div>
</template>
