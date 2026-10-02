<script setup lang="ts">
// Auto / Light / Dark, like the dashboard. The initial theme is set by an
// inline script in nuxt.config.ts, before first paint. `compact` is a single
// switch for phone-width headers: it follows the system until tapped, then
// flips between light and dark.
defineProps<{ compact?: boolean }>();

type Choice = "auto" | "light" | "dark";
// Shared by both instances (phone and wide header), so they never disagree.
const choice = useState<Choice>("theme-choice", () => "auto");
const options: Choice[] = ["auto", "light", "dark"];
// The theme actually showing, which is what the compact button reflects.
const isDark = useState("theme-dark", () => false);
// The server can't know the theme, so the knob may need to jump on load;
// only animate it after that, when someone taps it.
const ready = ref(false);

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
  requestAnimationFrame(() => requestAnimationFrame(() => (ready.value = true)));
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
    role="switch"
    :aria-checked="isDark"
    aria-label="Dark theme"
    class="relative h-6 w-10 rounded-full border border-line bg-bg-2 transition-colors"
    @click="pick(isDark ? 'light' : 'dark')"
  >
    <!-- The knob is the solid dot from the centre of the logo. -->
    <span
      class="absolute top-[3px] left-[3px] size-4 rounded-full bg-fg shadow-[0_0_0_3px_var(--bg-2)] duration-300 ease-[cubic-bezier(.65,0,.35,1)] motion-reduce:transition-none"
      :class="[isDark ? 'translate-x-4' : '', ready ? 'transition-transform' : '']"
      aria-hidden="true"
    />
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
