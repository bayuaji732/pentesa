"use client";

import React, { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useProject } from "@/lib/ProjectContext";
import { TopNav } from "@/components/TopNav";
import { Shield, RefreshCw } from "lucide-react";

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const pathname = usePathname();
  const router = useRouter();
  const { token, authLoading, currentUser } = useProject();

  const isLoginPage = pathname === "/login";

  useEffect(() => {
    if (!authLoading) {
      if (!token && !isLoginPage) {
        router.replace("/login");
      }
    }
  }, [token, authLoading, isLoginPage, router]);

  // If on /login page, show ONLY the sign-in page without TopNav, without extra wrapper padding
  if (isLoginPage) {
    return (
      <div className="min-h-screen w-full bg-slate-50 flex items-center justify-center">
        {children}
      </div>
    );
  }

  // If checking authentication for protected route, show sleek verification state
  if (authLoading) {
    return (
      <div className="min-h-screen w-full bg-slate-50 flex flex-col items-center justify-center select-none gap-3">
        <div className="h-10 w-10 rounded-xl bg-blue-900 border border-blue-800 flex items-center justify-center text-white shadow-md animate-pulse">
          <Shield className="h-5 w-5" />
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-600">
          <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-700" />
          <span>Authenticating SOC Session...</span>
        </div>
      </div>
    );
  }

  // If unauthenticated on a protected route, render blank while redirecting
  if (!token || !currentUser) {
    return null;
  }

  // Authenticated: Render full platform with TopNav and main viewport
  return (
    <>
      <TopNav />
      <main className="flex-1 overflow-y-auto bg-canvas p-4 sm:p-6 lg:p-8">
        <div className="max-w-[1600px] mx-auto w-full">
          {children}
        </div>
      </main>
    </>
  );
};

