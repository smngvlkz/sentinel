<script setup lang="ts">
const props = defineProps<{ lines: string[] }>();
const copied = ref(false);

async function copy() {
  // Copy the commands only, without trailing comments.
  const text = props.lines.map((l) => l.replace(/\s+#.*$/, "")).join("\n");
  try {
    await navigator.clipboard.writeText(text);
    copied.value = true;
    setTimeout(() => (copied.value = false), 1500);
  } catch {
    // Clipboard unavailable (e.g. insecure context); the text is still selectable.
  }
}
</script>

<template>
  <div class="relative rounded-lg border border-line bg-code">
    <pre class="overflow-x-auto p-4 pr-16 font-mono text-small leading-relaxed text-fg"><code><span v-for="(line, i) in lines" :key="i" class="block"><span class="select-none text-fg-muted">$ </span>{{ line.replace(/\s+#.*$/, "") }}<span v-if="/\s#/.test(line)" class="text-fg-3">{{ line.match(/\s+#.*$/)?.[0] }}</span></span></code></pre>
    <button
      type="button"
      class="absolute right-2 top-2 rounded-md border border-line bg-bg px-2 py-1 font-mono text-small text-fg-2 transition hover:text-fg"
      @click="copy"
    >
      {{ copied ? "Copied" : "Copy" }}
    </button>
  </div>
</template>
