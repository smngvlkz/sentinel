<script setup lang="ts">
import { dataset, days, resultNotes, resultsCaption, site } from "~/data/site";

const active = ref(days[0]!.id);
const tabs = ref<HTMLButtonElement[]>([]);

// Arrow keys move between tabs, as the ARIA tabs pattern expects.
function onKey(e: KeyboardEvent, i: number) {
  const to = e.key === "ArrowRight" ? (i + 1) % days.length : e.key === "ArrowLeft" ? (i - 1 + days.length) % days.length : -1;
  if (to < 0) return;
  e.preventDefault();
  active.value = days[to]!.id;
  tabs.value[to]?.focus();
}
</script>

<template>
  <section id="results" class="p-2 sm:p-4">
    <div class="well">
      <div class="mx-auto max-w-6xl px-4 py-20 sm:px-6">
        <SectionHeading
          eyebrow="Real numbers, real traffic"
          :title="'Tested on public data.\nMisses included.'"
          :lead="`Five full days of ${dataset.name} replayed through the real detection pipeline. Each labelled flow counts as caught only if SentinelAI alerted on that connection while it was happening.`"
        />

        <div class="lift mt-12 flex rounded-lg border border-line bg-bg p-0.5 text-body sm:inline-flex" role="tablist" aria-label="Test day">
          <button
            v-for="(d, i) in days"
            :id="`tab-${d.id}`"
            :key="d.id"
            ref="tabs"
            type="button"
            role="tab"
            class="flex-1 rounded-md px-2 py-1.5 font-medium transition sm:px-4"
            :class="active === d.id ? 'bg-bg-3 text-fg' : 'text-fg-3 hover:text-fg'"
            :aria-selected="active === d.id"
            :aria-controls="`panel-${d.id}`"
            :tabindex="active === d.id ? 0 : -1"
            @click="active = d.id"
            @keydown="onKey($event, i)"
          >
            <!-- Five days don't fit a phone's width by name; "Wed" does. -->
            <span class="sm:hidden" aria-hidden="true">{{ d.name.slice(0, 3) }}</span>
            <span class="max-sm:sr-only">{{ d.name }}</span>
          </button>
        </div>

        <article
          v-for="d in days"
          v-show="active === d.id"
          :id="`panel-${d.id}`"
          :key="d.id"
          role="tabpanel"
          :aria-labelledby="`tab-${d.id}`"
          class="lift mt-4 min-w-0 overflow-hidden rounded-xl border border-line bg-bg"
        >
          <header class="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-6 py-4">
            <span class="rounded-md border border-line px-2 py-0.5 font-mono text-small text-fg-2">{{ d.tag }}</span>
            <p class="text-body text-fg-2">{{ d.summary }}</p>
          </header>

          <p v-if="!d.rows.length" class="px-6 py-4 text-fg-2">No attacks this day, so there's nothing to catch: the rows below are all false alarms.</p>
          <table v-else class="w-full text-body">
            <thead>
              <tr class="border-b border-line text-left font-mono text-small uppercase tracking-wider text-fg-3">
                <th scope="col" class="px-6 py-3 font-normal">Attack</th>
                <th scope="col" class="hidden w-32 px-3 py-3 text-right font-normal sm:table-cell">Flows</th>
                <th scope="col" class="w-28 py-3 pl-3 pr-6 text-right font-normal sm:px-3">Caught</th>
                <th scope="col" class="hidden w-36 px-6 py-3 text-right font-normal sm:table-cell">Minutes</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-line">
              <tr v-for="r in d.rows" :key="r.attack">
                <th scope="row" class="px-6 py-3 text-left font-normal text-fg">{{ r.attack }}</th>
                <td class="hidden px-3 py-3 text-right font-mono text-fg-2 sm:table-cell">{{ r.flows }}</td>
                <td class="py-3 pl-3 pr-6 text-right font-mono sm:px-3" :class="r.missed ? 'text-high' : 'text-fg'">
                  {{ r.caught }}<span v-if="r.missed" class="sr-only"> (missed)</span>
                </td>
                <td class="hidden px-6 py-3 text-right font-mono text-fg-2 sm:table-cell">{{ r.minutes }}</td>
              </tr>
            </tbody>
          </table>

          <dl class="divide-y divide-line border-t border-line text-body">
            <div v-for="n in d.normal" :key="n.label" class="flex items-baseline justify-between gap-4 px-6 py-2.5">
              <dt class="text-fg-2">{{ n.label }}</dt>
              <dd class="shrink-0 font-mono text-fg">{{ n.value }}</dd>
            </div>
          </dl>
        </article>

        <p class="mt-4 text-small text-fg-3">{{ resultsCaption }}</p>

        <ul class="mt-10 max-w-3xl space-y-3 text-body text-fg-2">
          <li v-for="n in resultNotes" :key="n" class="flex gap-3">
            <span class="mt-[0.55rem] size-1 shrink-0 rounded-full bg-fg-muted" />
            {{ n }}
          </li>
        </ul>
        <p class="mt-8 text-body">
          <a :href="site.evaluationDoc" class="group text-link transition-colors hover:text-fg">Methodology, per-machine results and how to reproduce them <span class="inline-block transition-transform group-hover:translate-x-0.5" aria-hidden="true">→</span></a>
        </p>
      </div>
    </div>
  </section>
</template>
