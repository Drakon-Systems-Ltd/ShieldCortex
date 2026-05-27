import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/Providers";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ShieldCortex",
  description: "AI Memory Security Dashboard — Defence pipeline, audit logs, quarantine review",
};

// Inline theme bootstrap — runs before React hydration to set
// <html data-theme="…"> from localStorage. Prevents flash-of-wrong-theme
// when the user has chosen `glass` on a previous visit.
const themeBootstrap = `
try {
  var t = localStorage.getItem('sc-theme');
  if (t !== 'glass' && t !== 'terminal') t = 'terminal';
  document.documentElement.dataset.theme = t;
} catch (e) {
  document.documentElement.dataset.theme = 'terminal';
}
`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className="dark"
      data-theme="terminal"
      suppressHydrationWarning
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeBootstrap }} />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-slate-950`}
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
