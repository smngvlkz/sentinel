<script setup lang="ts">
import { site } from "~/data/site";
</script>

<template>
  <footer>
    <div class="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-10 text-body text-fg-3 sm:flex-row sm:items-center sm:px-6">
      <div class="flex items-center gap-2 text-fg-2">
        <Logo class="size-5" />
        <span>{{ site.name }}</span>
      </div>
      <p>{{ site.license }} licensed. Not a replacement for a professional security product.</p>
      <div class="flex items-center gap-4 sm:ml-auto">
        <a :href="site.repo" class="hover:text-fg">GitHub</a>
        <a :href="site.evaluationDoc" class="hover:text-fg">Evaluation</a>
        <a :href="site.roadmapDoc" class="hover:text-fg">Roadmap</a>
      </div>
    </div>
  </footer>
</template>
