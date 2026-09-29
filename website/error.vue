<script setup lang="ts">
import type { NuxtError } from "#app";

defineProps<{ error: NuxtError }>();
</script>

<template>
  <div class="grid min-h-screen place-items-center px-4">
    <div class="max-w-md text-center">
      <Logo class="mx-auto size-8 text-fg" />
      <p class="mt-6 font-mono text-small uppercase tracking-widest text-fg-3">Error {{ error.statusCode }}</p>
      <h1 class="mt-3 text-display font-semibold tracking-tight text-fg">
        {{ error.statusCode === 404 ? "Page not found." : "Something went wrong." }}
      </h1>
      <button
        type="button"
        class="mt-8 rounded-lg bg-accent px-5 py-2.5 text-body font-medium text-accent-fg transition hover:bg-accent-hover"
        @click="clearError({ redirect: '/' })"
      >Back to SentinelAI</button>
    </div>
  </div>
</template>
