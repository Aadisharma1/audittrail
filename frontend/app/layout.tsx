import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuditTrail Dashboard",
  description: "Centralized risk & audit logging",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
