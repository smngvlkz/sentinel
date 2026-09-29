<script setup lang="ts">
// Light and dark screenshots as a stack: the back card peeks out above and to
// the right. Only the Light / Dark switch changes which is in front; the
// cards shuffle (slide past each other, swapping order halfway) when it does.
import { screenshots } from "~/data/site";

type Theme = "light" | "dark";

const front = ref<Theme>("light");
const ready = ref(false); // no animation for the initial choice
const cards = [
  { theme: "light" as const, ...screenshots.light },
  { theme: "dark" as const, ...screenshots.dark },
];

function show(theme: Theme) {
  front.value = theme;
}

// Start with the screenshot matching the visitor's theme; after that, only the switch changes it.
onMounted(() => {
  if (document.documentElement.dataset.theme === "dark") front.value = "dark";
  requestAnimationFrame(() => (ready.value = true));
});
</script>

<template>
  <div>
    <div class="mb-4 flex justify-center">
      <!-- Same control as the header's theme switch (ThemeToggle.vue). -->
      <div class="flex rounded-lg border border-line bg-bg-2 p-0.5 text-small" role="group" aria-label="Screenshot theme">
        <button
          v-for="t in (['light', 'dark'] as const)"
          :key="t"
          type="button"
          class="rounded-md px-2.5 py-1 capitalize transition"
          :class="front === t ? 'bg-bg text-fg shadow-sm' : 'text-fg-3 hover:text-fg'"
          :aria-pressed="front === t"
          @click="show(t)"
        >{{ t }}</button>
      </div>
    </div>

    <div class="grid pr-[5%] pt-[6.5%]" :class="{ ready }">
      <figure
        v-for="c in cards"
        :key="c.theme"
        class="card col-start-1 row-start-1 overflow-hidden rounded-xl border border-line bg-bg-2"
        :class="front === c.theme ? 'is-front' : 'is-back'"
      >
        <img
          :src="c.src"
          :width="c.width"
          :height="c.height"
          :alt="c.theme === 'light' ? screenshots.alt : ''"
          class="block h-auto w-full"
          draggable="false"
        >
      </figure>
    </div>
  </div>
</template>

<style scoped>
.card {
  /* Anchored top-right, so the back card's offset shows in full. */
  transform-origin: 100% 0;
  will-change: transform;
}
.is-front {
  z-index: 2;
  transform: translate(0, 0) scale(1);
  box-shadow: 0 24px 48px -20px rgb(15 23 42 / 0.28);
}
.is-back {
  z-index: 1;
  transform: translate(5%, -10%) scale(0.92);
  box-shadow: 0 8px 20px -12px rgb(15 23 42 / 0.2);
}

/*
 * The shuffle: both cards glide to their new places while the stacking
 * order flips halfway through, so neither card jumps on top.
 */
.ready .card {
  transition:
    transform 0.7s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.7s ease,
    z-index 0s linear 0.3s;
}

@media (prefers-reduced-motion: reduce) {
  .ready .card {
    transition: none;
  }
}
</style>
