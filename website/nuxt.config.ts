import tailwindcss from "@tailwindcss/vite";

// Static site: `npm run generate` writes plain HTML to .output/public.
export default defineNuxtConfig({
  compatibilityDate: "2026-09-29",
  ssr: true,
  devtools: { enabled: false },
  telemetry: false,
  css: ["~/assets/css/main.css"],
  vite: { plugins: [tailwindcss()] },
  nitro: { prerender: { routes: ["/"], crawlLinks: false } },
  app: {
    head: {
      htmlAttrs: { lang: "en" },
      title: "SentinelAI: intrusion detection for your home network",
      meta: [
        { name: "viewport", content: "width=device-width, initial-scale=1" },
        {
          name: "description",
          content:
            "Open-source network intrusion detection for home and small-office networks. Spots port scans, floods and network sweeps, and explains each alert in plain language.",
        },
      ],
      link: [{ rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
      // Set the theme before first paint, from the saved choice or the OS, as the dashboard does.
      script: [
        {
          innerHTML:
            "try{var t=localStorage.getItem('theme');if(t!=='light'&&t!=='dark'){t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'}document.documentElement.dataset.theme=t}catch(e){}",
        },
      ],
    },
  },
});
