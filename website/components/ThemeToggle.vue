<script setup lang="ts">
// Auto / Light / Dark, like the dashboard. The initial theme is set by an
// inline script in nuxt.config.ts, before first paint.
type Choice = "auto" | "light" | "dark";
const choice = ref<Choice>("auto");
const options: Choice[] = ["auto", "light", "dark"];

function apply(c: Choice) {
  const dark = c === "dark" || (c === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

function pick(c: Choice) {
  choice.value = c;
  try {
    if (c === "auto") localStorage.removeItem("theme");
    else localStorage.setItem("theme", c);
  } catch {
    // Storage blocked: the choice still applies for this visit.
  }
  apply(c);
}

onMounted(() => {
  try {
    const saved = localStorage.getItem("theme");
    if (saved === "light" || saved === "dark") choice.value = saved;
  } catch {
    // Storage blocked: stay on auto.
  }
  matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (choice.value === "auto") apply("auto");
  });
});
</script>

<template>
  <div class="flex rounded-lg border border-line bg-bg-2 p-0.5 text-small" role="group" aria-label="Colour theme">
    <button
      v-for="o in options"
      :key="o"
      type="button"
      class="rounded-md px-2.5 py-1 capitalize transition"
      :class="choice === o ? 'bg-bg text-fg shadow-sm' : 'text-fg-3 hover:text-fg'"
      :aria-pressed="choice === o"
      @click="pick(o)"
    >
      {{ o }}
    </button>
  </div>
</template>
