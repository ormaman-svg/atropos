import type { Metadata } from "next";
import { Archivo, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";

/*
 * next/font downloads these at build time and serves them from our own origin.
 * The reference console pulls them from Google Fonts at runtime; we don't.
 * A product whose core promise is metadata discipline should not phone a third
 * party on every page load.
 */
const archivo = Archivo({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-archivo",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-plex-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Atropos",
  description: "Agent attack-path analysis.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${archivo.variable} ${plexMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
