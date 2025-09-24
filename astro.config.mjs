import { defineConfig } from 'astro/config';

import tailwindcss from '@tailwindcss/vite';
import mdx from '@astrojs/mdx';
import { oldBlogRedirects } from './redirects';
import rehypeExternalLinks from 'rehype-external-links';

export default defineConfig({
  site: 'https://idiot.sg',

  vite: {
    plugins: [tailwindcss()]
  },

  integrations: [mdx()],

  markdown: {
    shikiConfig: {
      theme: 'github-light'
    },
    rehypePlugins: [
      [rehypeExternalLinks, { target: '_blank', rel: ['noopener', 'noreferrer'] }],
    ]
  },

  redirects: {
    "/blog": "/blog/page/1",
    ...oldBlogRedirects,
  },
});