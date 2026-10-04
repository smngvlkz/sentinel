import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import "./globals.css";

// Shipped in ./fonts (Latin subsets, from Fontsource; licences beside them)
// rather than fetched from Google Fonts on every build, which made builds
// need the internet and failed at random when Google served a font URL
// Next.js couldn't parse.
const inter = localFont({
  variable: "--font-inter",
  src: "./fonts/inter-latin-wght-normal.woff2",
  weight: "100 900",
});

const jetbrains = localFont({
  variable: "--font-jetbrains",
  src: [
    { path: "./fonts/jetbrains-mono-latin-400-normal.woff2", weight: "400" },
    { path: "./fonts/jetbrains-mono-latin-500-normal.woff2", weight: "500" },
  ],
});

export const metadata: Metadata = {
  title: "SentinelAI",
  description: "Watch your network for intrusions, explained in plain language.",
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#1d1d20" },
  ],
};

// Runs before first paint so the saved theme applies without a flash.
// "system" (or nothing saved) follows the OS setting.
const themeScript = `(function(){try{var t=localStorage.getItem("theme");if(t!=="light"&&t!=="dark"){t=matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"}document.documentElement.dataset.theme=t}catch(e){}})()`;

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body className={`${inter.variable} ${jetbrains.variable} antialiased`}>{children}</body>
    </html>
  );
}
