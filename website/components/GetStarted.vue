<script setup lang="ts">
import { Cpu, SquareTerminal } from "lucide-vue-next";
import { install } from "~/data/site";
</script>

<template>
  <section id="get-started" class="border-b border-line">
    <div class="mx-auto max-w-6xl px-4 py-20 sm:px-6">
      <SectionHeading eyebrow="Get started" title="Run it on your own network." />
      <div class="mt-12 grid gap-6 lg:grid-cols-2">
        <article class="flex min-w-0 flex-col rounded-xl border border-line p-6">
          <h3 class="flex items-center gap-2.5 font-medium text-fg">
            <SquareTerminal class="size-5 text-fg-3" :stroke-width="1.5" aria-hidden="true" />
            {{ install.source.title }}
          </h3>
          <p class="mt-3 text-fg-2">{{ install.source.body }}</p>
          <CodeBlock class="mt-6" :lines="install.source.commands" />
          <p class="mt-4 text-fg-3">{{ install.source.next }}</p>
        </article>

        <article class="flex min-w-0 flex-col rounded-xl border border-line p-6">
          <div class="flex items-center justify-between gap-3">
            <h3 class="flex items-center gap-2.5 font-medium text-fg">
              <Cpu class="size-5 text-fg-3" :stroke-width="1.5" aria-hidden="true" />
              {{ install.pi.title }}
            </h3>
            <span class="rounded-md border border-line px-2 py-0.5 font-mono text-small uppercase tracking-wider text-fg-3">Planned</span>
          </div>
          <p class="mt-3 text-fg-2">{{ install.pi.body }}</p>
          <p class="mt-6 flex flex-1 items-center rounded-lg border border-dashed border-line-strong p-4 text-fg-3">
            <span>
              Install steps will appear here once the Raspberry Pi installer is built.
              <a href="#next" class="text-link transition-colors hover:text-fg">See what's next</a>.
            </span>
          </p>
        </article>
      </div>
      <p class="mt-8 text-body text-fg-3">Only monitor networks you own or have explicit permission to monitor.</p>
    </div>
  </section>
</template>
