<script setup lang="ts">
import { site } from "~/data/site";

const links = [
  { href: "#results", label: "Results" },
  { href: "#features", label: "Features" },
  { href: "#limits", label: "Limits" },
  { href: "#faq", label: "FAQ" },
];
</script>

<template>
  <header class="sticky top-0 z-30 border-b border-line bg-bg/85 backdrop-blur">
    <div class="flex h-16 w-full items-center gap-6 px-4 sm:px-6 lg:px-10">
      <a href="#top" class="flex items-center gap-2.5 text-fg">
        <Logo class="size-6" />
        <span class="text-body font-semibold tracking-tight">{{ site.name }}</span>
        <span class="rounded-md border border-line px-1.5 py-0.5 font-mono text-small text-fg-3">v{{ site.version }}</span>
      </a>
      <nav class="ml-auto hidden items-center gap-6 text-body text-fg-2 md:flex" aria-label="Sections">
        <a v-for="l in links" :key="l.href" :href="l.href" class="transition hover:text-fg">{{ l.label }}</a>
      </nav>
      <div class="ml-auto flex items-center gap-3 md:ml-0">
        <ThemeToggle class="hidden sm:flex" />
        <a
          :href="site.repo"
          class="rounded-lg border border-line px-3 py-1.5 text-body text-fg transition hover:bg-bg-2"
        >GitHub</a>
      </div>
    </div>
  </header>
</template>
