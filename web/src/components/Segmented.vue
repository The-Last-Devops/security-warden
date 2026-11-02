<script setup>
defineProps({ modelValue: String, options: Array, label: String })
defineEmits(['update:modelValue'])
</script>

<template>
  <div class="inline-flex rounded-[10px] border border-line bg-panel2 p-0.5" role="radiogroup" :aria-label="label">
    <button v-for="o in options" :key="o.value" type="button" role="radio" :aria-checked="modelValue === o.value"
      class="rounded-lg px-2.5 py-1 text-[12.5px] font-semibold transition-colors"
      :class="modelValue === o.value ? 'bg-accent text-accent-ink' : 'text-muted hover:text-fg'"
      @click="$emit('update:modelValue', o.value)">{{ o.label }}</button>
  </div>
</template>
