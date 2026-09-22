import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { SearchBox } from "@/components/SearchBox";

const sans = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-sans",
  fallback: ["system-ui", "Segoe UI", "sans-serif"],
});

const mono = JetBrains_Mono({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-mono",
  weight: ["400", "500"],
  fallback: ["ui-monospace", "Consolas", "monospace"],
});

export const metadata: Metadata = {
  title: { default: "Asber", template: "%s · Asber" },
  description: "Asber — watch, correlate and prioritise cyber threats from public sources",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <div className="app">
          <Sidebar />
          <main className="main">
            <SearchBox />
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
