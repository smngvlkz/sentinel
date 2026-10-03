<script setup lang="ts">
import { CheckCheck, CirclePlay, Gauge, Lock, MessageSquareText, Radar, Shuffle, Tag } from "lucide-vue-next";
import { features, type FeatureIcon } from "~/data/site";

// Same icon set as the dashboard (lucide); Shuffle is its "Unusual traffic" icon.
const icons: Record<FeatureIcon, unknown> = {
  radar: Radar,
  tag: Tag,
  message: MessageSquareText,
  check: CheckCheck,
  shuffle: Shuffle,
  gauge: Gauge,
  lock: Lock,
  play: CirclePlay,
};
</script>

<template>
  <section id="features">
    <div class="mx-auto max-w-6xl px-4 py-20 sm:px-6">
      <SectionHeading
        eyebrow="Features"
        :title="'Small enough to understand,\nuseful enough to run.'"
        lead="A handful of readable rules, a dashboard that explains itself, and everything on your own hardware."
      />
      <!-- One bordered grid; 1px gaps over the line colour draw the dividers. -->
      <div class="mt-12 grid gap-px overflow-hidden rounded-xl border border-line bg-line md:grid-cols-2">
        <article
          v-for="(f, i) in features"
          :key="f.tag"
          class="bg-bg p-8 transition-colors duration-200 hover:bg-bg-3"
          :class="{ 'md:col-span-2': i === features.length - 1 && features.length % 2 === 1 }"
        >
          <component :is="icons[f.icon]" class="size-5 text-fg-3" :stroke-width="1.5" aria-hidden="true" />
          <p class="mt-5 font-mono text-small uppercase tracking-wider text-fg-3">
            {{ String(i + 1).padStart(2, "0") }} — {{ f.tag }}
          </p>
          <h3 class="mt-3 font-medium text-fg">{{ f.title }}</h3>
          <p class="mt-2 text-fg-2">{{ f.body }}</p>
          <ul v-if="f.points" class="mt-3 space-y-1 text-fg-2">
            <li v-for="p in f.points" :key="p" class="flex gap-2.5">
              <span class="mt-[0.65rem] size-1 shrink-0 rounded-full bg-fg-muted" />
              {{ p }}
            </li>
          </ul>
        </article>
      </div>
    </div>
  </section>
</template>
