import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/Sidebar";
import { SearchBox } from "@/components/SearchBox";
import { AccountMenu } from "@/components/AccountMenu";
import { auth } from "@/auth";

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

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Signed-out visitors only ever reach /login (the middleware guarantees it),
  // which is rendered bare — the dashboard shell would be empty anyway.
  const session = await auth();

  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        {session?.user ? (
          <div className="app">
            <Sidebar />
            <main className="main">
              <div className="topbar-row">
                <SearchBox />
                <AccountMenu user={session.user} />
              </div>
              {children}
            </main>
          </div>
        ) : (
          children
        )}
      </body>
    </html>
  );
}
