import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "@/components/Providers";
import { CicEffects } from "@/components/cic/CicEffects";

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

// Runs before paint: resolve the persisted theme so the CIC terminal look (or a
// previously-chosen glass) is applied with no flash. Defaults to terminal.
const THEME_BOOTSTRAP = `try{var t=localStorage.getItem('sc-theme');document.documentElement.setAttribute('data-theme',t==='glass'?'glass':'terminal');}catch(e){}`;

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
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOTSTRAP }} />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <CicEffects />
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
