import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

export default defineConfig({
  site: "https://closeout.fyi",
  integrations: [sitemap()],
  trailingSlash: "never",
});
