<script setup lang="ts">
import { limits } from "~/data/site";
</script>

<template>
  <section id="limits" class="p-2 sm:p-4">
    <div class="well">
      <div class="mx-auto max-w-6xl px-4 py-20 sm:px-6">
        <SectionHeading
          eyebrow="What it can't do"
          :title="'Know the blind spots\nbefore you rely on it.'"
        />
        <div class="lift mt-12 grid gap-px overflow-hidden rounded-xl border border-line bg-line sm:grid-cols-2">
          <div v-for="l in limits" :key="l.title" class="bg-bg p-6 transition-colors duration-200 hover:bg-bg-3 sm:last:odd:col-span-2">
            <h3 class="font-medium text-fg">{{ l.title }}</h3>
            <p class="mt-2 text-body text-fg-2">{{ l.body }}</p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>
