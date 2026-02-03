import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'APKspider Analysis Console',
  description: 'Secure APK/XAPK analysis and reporting.'
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen font-sans">
        {children}
      </body>
    </html>
  );
}
