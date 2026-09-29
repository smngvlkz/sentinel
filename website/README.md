# SentinelAI website

The landing page, built with Nuxt 3 and Tailwind CSS as a static site. It has
no backend.

```bash
npm install
npm run dev        # http://localhost:3000
npm run generate   # static HTML in .output/public
npm run typecheck
```

- **Numbers and most of the copy** live in [`data/site.ts`](data/site.ts);
  section headings are in the components. Update it whenever
  [`docs/evaluation.md`](../docs/evaluation.md) changes.
- **Version:** `site.version` shows in the header and hero. Change it with
  each release, together with the app's own version, fresh dashboard
  screenshots and `public/og.png` (the link-preview image, which shows the
  version too).
- **Built vs planned:** `features` lists only what works today. Anything
  planned goes in `next`, which the page labels "Planned" and links to
  `docs/ROADMAP.md`. Move an item across only once it's built and tested.
- **Style:** colours come from the dashboard
  (`dashboard/src/app/globals.css`). Keep the two in step.
- **Fonts** are bundled, so the page makes no requests to font services.

## Deploying

The site deploys to [sentinelids.com](https://sentinelids.com) with Cloudflare
Pages, which rebuilds it on every push to `master`:

| Setting | Value |
|---|---|
| Root directory | `website` |
| Build command | `npm run generate` |
| Build output directory | `.output/public` |
| Node version | from `.node-version` |

Pull requests get their own preview address. The page declares
`https://sentinelids.com/` as its canonical address, so search engines index
that rather than the previews.
