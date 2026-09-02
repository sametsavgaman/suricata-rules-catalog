import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? 'https://suricata-rule-agent-mimari.ssvg.chatgpt.site'),
  title: 'Suricata Rule Agent — Mimari Rehberi',
  description: 'Suricata Rule Agent projesinin mimarisi, veri akışı ve dosya rehberi.',
  openGraph: {
    title: 'Suricata Rule Agent — Mimari Rehberi',
    description: 'Mimariyi, uçtan uca veri akışını ve her dosyanın sorumluluğunu keşfedin.',
    images: [{ url: '/og.png', width: 1200, height: 630, alt: 'Suricata Rule Agent mimari akışı' }],
    locale: 'tr_TR',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Suricata Rule Agent — Mimari Rehberi',
    description: 'Mimariyi, uçtan uca veri akışını ve her dosyanın sorumluluğunu keşfedin.',
    images: ['/og.png'],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="tr">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
