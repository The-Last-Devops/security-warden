<script setup>
// Marks a check that is not part of the reviewed core set: community (on by
// default, reviewed) or experimental (opt-in, waiting for review).
defineProps({ tier: String, t: Object })
</script>

<template>
  <span v-if="tier === 'community' || tier === 'experimental'"
    class="inline-block shrink-0 rounded-full px-2 py-0.5 text-[11px] leading-tight font-bold whitespace-nowrap ring-1"
    :class="tier === 'experimental' ? 'bg-med-bg text-med ring-med/30' : 'bg-accent-soft text-accent ring-accent/30'">{{ t.tier[tier] }}</span>
</template>
