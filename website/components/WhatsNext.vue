<script setup lang="ts">
import { BellRing, Cpu, HardDrive, Sparkles } from "lucide-vue-next";
import { next, site, type NextIcon } from "~/data/site";

const icons: Record<NextIcon, unknown> = { disk: HardDrive, cpu: Cpu, bell: BellRing, sparkles: Sparkles };
</script>

<template>
  <section id="next">
    <div class="mx-auto max-w-6xl px-4 py-20 sm:px-6">
      <SectionHeading
        eyebrow="What's next"
        title="Planned, not built yet."
        lead="None of this exists today. Each has a written plan, with what it must do before it ships."
      />
      <div class="mt-12 grid gap-px overflow-hidden rounded-xl border border-line bg-line md:grid-cols-2 lg:grid-cols-4">
        <article v-for="n in next" :key="n.title" class="bg-bg p-6 transition-colors duration-200 hover:bg-bg-3">
          <div class="flex items-center justify-between gap-3">
            <component :is="icons[n.icon]" class="size-5 text-fg-3" :stroke-width="1.5" aria-hidden="true" />
            <span class="rounded-md border border-line px-2 py-0.5 font-mono text-small uppercase tracking-wider text-fg-3">Planned</span>
          </div>
          <h3 class="mt-5 font-medium text-fg">{{ n.title }}</h3>
          <p class="mt-2 text-fg-2">{{ n.body }}</p>
        </article>
      </div>
      <p class="mt-8">
        <a :href="site.roadmapDoc" class="group text-link transition-colors hover:text-fg">
          Read the roadmap <span class="inline-block transition-transform group-hover:translate-x-0.5" aria-hidden="true">→</span>
        </a>
      </p>
    </div>
  </section>
</template>
