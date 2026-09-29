<script setup lang="ts">
import { site } from "~/data/site";
</script>

<template>
  <section id="top">
    <div class="mx-auto max-w-6xl px-4 pb-16 pt-16 sm:px-6 sm:pt-24">
      <div class="max-w-5xl">
        <p class="font-mono text-small uppercase tracking-widest text-fg-3">Open source · {{ site.license }} · v{{ site.version }}</p>
        <h1 class="mt-5 whitespace-pre-line text-display font-semibold tracking-tight text-fg">{{ site.pitch }}</h1>
        <p class="mt-6 max-w-2xl text-body text-fg-2">{{ site.subPitch }}</p>
        <div class="mt-8 flex flex-wrap items-center gap-3">
          <a
            href="#get-started"
            class="rounded-lg bg-accent px-5 py-2.5 text-body font-medium text-accent-fg transition hover:bg-accent-hover"
          >Install</a>
          <a
            :href="site.repo"
            class="rounded-lg border border-line px-5 py-2.5 text-body font-medium text-fg transition hover:bg-bg-2"
          >View on GitHub</a>
        </div>
      </div>

      <DashboardStack class="mt-10" />
    </div>
  </section>
</template>
