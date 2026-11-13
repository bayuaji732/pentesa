import React from "react";
import type { Metadata } from "next";
import "./globals.css";
import { ProjectProvider } from "@/lib/ProjectContext";
import { ToastProvider } from "@/lib/ToastContext";
import { AppShell } from "@/components/AppShell";

export const metadata: Metadata = {
  title: "Pentesa — Autonomous Penetration Testing Platform",
  description: "Enterprise Autonomous Web Application Penetration Testing Platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-canvas text-slate-900 flex flex-col h-screen overflow-hidden font-sans antialiased">
        <ToastProvider>
          <ProjectProvider>
            <AppShell>{children}</AppShell>
          </ProjectProvider>
        </ToastProvider>
      </body>
    </html>
  );
}
