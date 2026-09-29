<script setup lang="ts">
defineProps<{ eyebrow: string; title: string; lead?: string }>();
</script>

<template>
  <div class="max-w-3xl">
    <p class="font-mono text-small uppercase tracking-widest text-fg-3">{{ eyebrow }}</p>
    <!-- A "\n" in the title is a deliberate line break. -->
    <h2 class="mt-3 whitespace-pre-line text-display font-semibold tracking-tight text-fg">{{ title }}</h2>
    <p v-if="lead" class="mt-4 text-body text-fg-2">{{ lead }}</p>
  </div>
</template>
