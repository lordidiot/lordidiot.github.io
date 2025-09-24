import rss from '@astrojs/rss';
import { getCollection } from 'astro:content';

export async function GET(context) {
  const blog = await getCollection('blog');
  return rss({
    // `<title>` field in output xml
    title: 'Lord_Idiot\'s personal page',
    // `<description>` field in output xml
    description: 'Writing about AI, software, security and anything else that interests me.',
    // Pull in your project "site" from the endpoint context
    // https://docs.astro.build/en/reference/api-reference/#site
    site: context.site,
    // Array of `<item>`s in output xml
    // See "Generating items" section for examples using content collections and glob imports
    items: blog.map(post => ({
      title: post.data.title,
      pubDate: post.data.pubDate,
      description: post.data.description,
      link: `/blog/${post.slug}`,
    })),
    // (optional) inject custom xml
    customData: `<language>en-us</language>`,
  });
}