import React from "react";
import type { Metadata } from "next";
import "./globals.css";
import { ProjectProvider } from "@/lib/ProjectContext";
import { TopNav } from "@/components/TopNav";
import { Sidebar } from "@/components/Sidebar";

export const metadata: Metadata = {
  title: "Pentesa — Autonomous Security Operations Center",
  description: "AI-Powered Autonomous Web Application Penetration Testing Platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-canvas text-slate-100 flex flex-col h-screen overflow-hidden">
        <ProjectProvider>
          <TopNav />
          <div className="flex flex-1 overflow-hidden">
            <Sidebar />
            <main className="flex-1 overflow-y-auto bg-canvas p-6">
              {children}
            </main>
          </div>
        </ProjectProvider>
      </body>
    </html>
  );
}

