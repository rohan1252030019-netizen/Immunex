import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-sans",
  subsets: ["latin"],
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
  display: 'swap',
});

export const metadata: Metadata = {
  title: "IMMUNEX Enterprise SOC | Autonomous AI Cyber-Defense Console",
  description: "Next-generation military-grade autonomous cyber-defense console powered by multi-model consensus, active attack graphs, and local RAG intelligence.",
  keywords: ["SOC", "Cybersecurity", "Autonomous SOC", "AI Cyber-Defense", "MITRE ATT&CK", "Attack Graph"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full scroll-smooth">
      <body className={`${inter.variable} ${jetbrainsMono.variable} font-sans antialiased h-full bg-[#050814] text-white flex flex-col`}>
        {children}
      </body>
    </html>
  );
}
