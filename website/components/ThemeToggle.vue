<script setup lang="ts">
import { Moon, Sun } from "lucide-vue-next";

// Auto / Light / Dark, like the dashboard. The initial theme is set by an
// inline script in nuxt.config.ts, before first paint. `compact` is a single
// sun/moon button for phone-width headers: it follows the system until
// tapped, then flips between light and dark.
defineProps<{ compact?: boolean }>();

type Choice = "auto" | "light" | "dark";
// Shared by both instances (phone and wide header), so they never disagree.
const choice = useState<Choice>("theme-choice", () => "auto");
const options: Choice[] = ["auto", "light", "dark"];
// The theme actually showing, which decides what the compact button does.
const isDark = useState("theme-dark", () => false);

function apply(c: Choice) {
  isDark.value = c === "dark" || (c === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = isDark.value ? "dark" : "light";
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
  isDark.value = document.documentElement.dataset.theme === "dark";
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
  <button
    v-if="compact"
    type="button"
    class="theme-toggle flex size-9 items-center justify-center rounded-lg border border-line text-fg-2 transition hover:bg-bg-2 hover:text-fg"
    :aria-label="isDark ? 'Switch to light theme' : 'Switch to dark theme'"
    :title="isDark ? 'Light theme' : 'Dark theme'"
    @click="pick(isDark ? 'light' : 'dark')"
  >
    <!-- Shows the theme you'd switch to. CSS picks the icon from data-theme on
         <html>, which is set before first paint, so it's right on load. -->
    <Moon class="theme-toggle-moon size-4" :stroke-width="1.75" aria-hidden="true" />
    <Sun class="theme-toggle-sun size-4" :stroke-width="1.75" aria-hidden="true" />
  </button>
  <div v-else class="flex rounded-lg border border-line bg-bg-2 p-0.5 text-small" role="group" aria-label="Colour theme">
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

<style>
.theme-toggle-sun { display: none; }
:root[data-theme="dark"] .theme-toggle-sun { display: block; }
:root[data-theme="dark"] .theme-toggle-moon { display: none; }
</style>
