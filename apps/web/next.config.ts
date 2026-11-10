import type { NextConfig } from 'next';

const config: NextConfig = {
  transpilePackages: ['@fortis/shared'],
  poweredByHeader: false,
  // The CLI docs moved to the website. Old links to /docs (from npm, emails, bookmarks) follow them there.
  async redirects() {
    return [{ source: '/docs/:path*', destination: 'https://fortis.dev/docs.html', permanent: false }];
  },
  // /api/* is proxied to the API by src/app/api/[...path]/route.ts, using API_URL at run time.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },
};

export default config;
