import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/Providers";

export const metadata: Metadata = {
  title: "ShieldCortex",
  description: "AI Memory Security Dashboard — Defence pipeline, audit logs, quarantine review",
};

// Runs before paint: resolve the persisted theme preference (light|dark|system;
// legacy terminal/glass → dark) and set the `dark` class so there is no flash.
// Dark is the default (brand: electric blue on deep navy); a light or system
// user swaps before first paint.
const THEME_BOOTSTRAP = `try{var t=localStorage.getItem('sc-theme');if(t==='terminal'||t==='glass'){t='dark';localStorage.setItem('sc-theme','dark');}if(t!=='light'&&t!=='dark'&&t!=='system'){t='dark';}var d=t==='dark'||(t==='system'&&window.matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d);document.documentElement.style.colorScheme=d?'dark':'light';}catch(e){}`;

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
      <body className="antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
