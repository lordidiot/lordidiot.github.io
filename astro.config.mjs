import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';
import mdx from '@astrojs/mdx';

export default defineConfig({
  site: 'https://lordidiot.github.io',

  vite: {
    plugins: [tailwindcss()]
  },

  integrations: [mdx()],

  markdown: {
    shikiConfig: {
      theme: 'github-light'
    }
  },

  redirects: {
    "/blog": "/blog/page/1"
  },
});