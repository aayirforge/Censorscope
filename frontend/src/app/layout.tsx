import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CensorScope | Empirical Censorship Telemetry for India",
  description: "Verifiable, per-ISP domain accessibility and network interference telemetry.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 antialiased selection:bg-indigo-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
