import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';

import { ToastProvider } from '@/components/ui';

import './globals.css';

export const metadata: Metadata = {
  title: { default: 'Fortis', template: '%s · Fortis' },
  description: 'Security testing on every release, for African fintech.',
  icons: { icon: '/favicon.svg' },
};

export const viewport: Viewport = { themeColor: '#071632' };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Instrument+Serif:ital@0;1&family=JetBrains+Mono:wght@400;600;700&display=swap"
        />
      </head>
      <body>
        <ToastProvider>{children}</ToastProvider>
      </body>
    </html>
  );
}
