import React from "react";
import type { Metadata } from "next";
import "./globals.css";
import { ProjectProvider } from "@/lib/ProjectContext";
import { ToastProvider } from "@/lib/ToastContext";
import { TopNav } from "@/components/TopNav";

export const metadata: Metadata = {
  title: "Pentesa — Autonomous Pentest Engine",
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
            <TopNav />
            <main className="flex-1 overflow-y-auto bg-canvas p-4 sm:p-6 lg:p-8">
              <div className="max-w-[1600px] mx-auto w-full">
                {children}
              </div>
            </main>
          </ProjectProvider>
        </ToastProvider>
      </body>
    </html>
  );
}
