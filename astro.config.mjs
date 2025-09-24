import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';
import mdx from '@astrojs/mdx';
import { oldBlogRedirects } from './redirects';

export default defineConfig({
  site: 'https://idiot.sg',

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
    "/blog": "/blog/page/1",
    ...oldBlogRedirects,
  },
});