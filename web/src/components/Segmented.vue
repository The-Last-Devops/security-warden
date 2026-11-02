<script setup>
// A small segmented control: options [{ value, label, title }].
defineProps({ modelValue: String, options: Array, label: String })
defineEmits(['update:modelValue'])
</script>

<template>
  <div class="inline-flex rounded-lg border border-line bg-side p-0.5" role="radiogroup" :aria-label="label">
    <button v-for="o in options" :key="o.value" type="button" role="radio" :aria-checked="modelValue === o.value" :title="o.title || o.label"
      class="rounded-md px-2.5 py-1 text-[13px] font-semibold transition-colors"
      :class="modelValue === o.value ? 'bg-accent text-accent-ink shadow-sm' : 'text-fg/70 hover:text-fg'"
      @click="$emit('update:modelValue', o.value)">
{{ o.label }}
    </button>
  </div>
</template>
