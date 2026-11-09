"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, Mail, AlertCircle, ArrowRight } from "lucide-react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";

export default function LoginPage() {
  const router = useRouter();
  const { refreshProjects } = useProject();
  const [email, setEmail] = useState("admin@example.com");
  const [password, setPassword] = useState("Admin123!Secure");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await api.login(email, password);
      await refreshProjects();
      router.push("/");
    } catch (err: any) {
      const msg = typeof err?.message === "string" 
        ? err.message 
        : typeof err?.data?.detail === "string" 
        ? err.data.detail 
        : "Invalid credentials or backend unreachable";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen -m-6 flex items-center justify-center bg-canvas p-4 select-none">
      <div className="w-full max-w-md bg-surface-base border border-slate-800 rounded-xl p-8 shadow-2xl space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-12 w-12 rounded-xl bg-red-950/80 border border-red-800/80 items-center justify-center text-red-400 mb-2">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-slate-100">
            PENTESA SOC CONSOLE
          </h1>
          <p className="text-xs text-slate-400 font-mono">
            Autonomous Web Application Penetration Testing Platform
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-lg flex items-center gap-2.5 text-red-400 text-xs">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Operator Email</label>
            <div className="relative">
              <Mail className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@example.com"
                className="w-full h-9 pl-9 pr-3 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500 font-mono"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Master Secret Password</label>
            <div className="relative">
              <Lock className="h-4 w-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full h-9 pl-9 pr-3 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500 font-mono"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full h-9 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded-md transition-colors flex items-center justify-center gap-2 shadow-lg shadow-red-950/40 disabled:opacity-50"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Authenticating...
              </span>
            ) : (
              <>
                <span>Sign In to Operations Console</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </>
            )}
          </button>
        </form>

        <div className="pt-2 border-t border-slate-800 text-center">
          <p className="text-[11px] text-slate-500 font-mono">
            Default credentials: <code className="text-slate-400">admin@example.com</code> / <code className="text-slate-400">Admin123!Secure</code>
          </p>
        </div>
      </div>
    </div>
  );
}

