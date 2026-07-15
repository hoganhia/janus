import type { Metadata } from 'next';
import { Inter, JetBrains_Mono } from 'next/font/google';
import { Topbar } from '@/components/topbar';
import './globals.css';

const inter = Inter({
  variable: '--font-inter',
  subsets: ['latin'],
  weight: ['400', '500', '600'],
});

const jetbrainsMono = JetBrains_Mono({
  variable: '--font-jetbrains-mono',
  subsets: ['latin'],
  weight: ['400', '500', '700', '800'],
});

export const metadata: Metadata = {
  title: 'Perimeter // external security scan',
  description:
    'See what the internet already sees about your site — passive, read-only, takes ~20 seconds.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} ${jetbrainsMono.variable} min-h-screen antialiased`}>
        <Topbar />
        {children}
      </body>
    </html>
  );
}
