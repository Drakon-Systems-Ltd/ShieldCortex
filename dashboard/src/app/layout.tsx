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

// Runs before paint: resolve the persisted theme preference (light|dark|system;
// legacy terminal/glass → dark) and set the `dark` class so there is no flash.
// SSR default is dark; a light user swaps before first paint.
const THEME_BOOTSTRAP = `try{var t=localStorage.getItem('sc-theme');if(t==='terminal'||t==='glass'){t='dark';localStorage.setItem('sc-theme','dark');}if(t!=='light'&&t!=='dark'&&t!=='system'){t='system';}var d=t==='dark'||(t==='system'&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);document.documentElement.style.colorScheme=d?'dark':'light';}catch(e){}`;

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
