import type { ReactNode } from "react";
import { JetBrains_Mono } from "next/font/google";
import "./globals.css";

// JetBrains Mono is the single family for the whole console, as in
// pod_forensics. next/font self-hosts it at build time, so the deployed page
// makes no external font request and needs no CDN at runtime.
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  display: "swap",
  variable: "--font-mono",
});

export const metadata = {
  title: "alert_forensics // model x scenario eval",
  description:
    "SOC alert triage scored against ground truth across models and scenarios, with every claim cited to a tool call and every proportion carrying its Wilson interval.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={jetbrainsMono.variable}>
      <body>{children}</body>
    </html>
  );
}
