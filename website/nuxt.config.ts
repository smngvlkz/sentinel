import tailwindcss from "@tailwindcss/vite";

const SITE_URL = "https://sentinelids.com";
const TITLE = "SentinelAI: intrusion detection for your home network";
const DESCRIPTION =
  "Open-source network intrusion detection for home and small-office networks. Spots port scans, floods and network sweeps, and explains each alert in plain language.";

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
      title: TITLE,
      meta: [
        { name: "viewport", content: "width=device-width, initial-scale=1" },
        { name: "description", content: DESCRIPTION },
        // Link previews (X, LinkedIn, Slack and others). public/og.png shows the version: update it each release.
        { property: "og:type", content: "website" },
        { property: "og:site_name", content: "SentinelAI" },
        { property: "og:url", content: `${SITE_URL}/` },
        { property: "og:title", content: TITLE },
        { property: "og:description", content: DESCRIPTION },
        { property: "og:image", content: `${SITE_URL}/og.png` },
        { property: "og:image:width", content: "2400" },
        { property: "og:image:height", content: "1260" },
        { property: "og:image:alt", content: "SentinelAI: intrusion detection for your home network, explained in plain language" },
        { name: "twitter:card", content: "summary_large_image" },
      ],
      link: [
        { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" },
        // The official address, so search engines don't index preview deployments instead.
        { rel: "canonical", href: `${SITE_URL}/` },
      ],
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
