<script setup lang="ts">
import { faqs } from "~/data/site";
</script>

<template>
  <section id="faq" class="p-2 sm:p-4">
    <div class="well">
      <div class="mx-auto grid max-w-6xl gap-12 px-4 py-20 sm:px-6 lg:grid-cols-[1fr_2fr]">
        <SectionHeading eyebrow="FAQ" :title="'Questions\npeople ask.'" />
        <div class="lift divide-y divide-line self-start rounded-xl border border-line bg-bg px-6">
          <details v-for="f in faqs" :key="f.q" class="group py-5">
            <summary class="flex cursor-pointer list-none items-start justify-between gap-6 font-medium text-fg [&::-webkit-details-marker]:hidden">
              <span>{{ f.q }}</span>
              <span class="mt-0.5 font-mono text-fg-3 transition group-open:rotate-45" aria-hidden="true">+</span>
            </summary>
            <p class="mt-3 text-fg-2">{{ f.a }}</p>
          </details>
        </div>
      </div>
    </div>
  </section>
</template>
