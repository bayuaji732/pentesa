"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, Mail, AlertCircle, ArrowRight, Eye, EyeOff } from "lucide-react";
import { api } from "@/lib/api";
import { useProject } from "@/lib/ProjectContext";

export default function LoginPage() {
  const router = useRouter();
  const { refreshProjects } = useProject();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined" && window.location.search.includes("expired=1")) {
      setSessionExpired(true);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await api.login(email, password);
      await refreshProjects();
      router.push("/projects");
    } catch (err: any) {
      const msg =
        typeof err?.message === "string"
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
    <div className="w-full max-w-md bg-white border border-slate-200/90 rounded-xl p-8 shadow-sm space-y-6 m-4 select-none">
      {/* Brand Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex h-12 w-12 rounded-xl bg-blue-900 border border-blue-800 items-center justify-center text-white shadow-xs mx-auto mb-2">
          <Shield className="h-6 w-6" />
        </div>
        <h1 className="text-xl font-bold tracking-tight text-slate-900">
          PENTESA SOC CONSOLE
        </h1>
        <p className="text-xs text-slate-500 font-medium">
          Autonomous Penetration Testing Platform
        </p>
      </div>

      {/* Session Expired Alert */}
      {sessionExpired && !error && (
        <div className="p-3 bg-amber-50 border border-amber-200 rounded-md flex items-center gap-2.5 text-amber-800 text-xs font-medium">
          <AlertCircle className="h-4 w-4 shrink-0 text-amber-600" />
          <span>Session Expired: Your credentials or token have expired. Please sign in again.</span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-3 bg-rose-50 border border-rose-200 rounded-md flex items-center gap-2.5 text-rose-800 text-xs font-medium">
          <AlertCircle className="h-4 w-4 shrink-0 text-rose-600" />
          <span>{error}</span>
        </div>
      )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-700">Email</label>
            <div className="relative">
              <Mail className="h-4 w-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder=""
                autoComplete="email"
                className="w-full h-10 pl-9 pr-3 bg-white border border-slate-300 rounded-md text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 shadow-xs transition-[color,box-shadow]"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-700">Password</label>
            <div className="relative">
              <Lock className="h-4 w-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
              <input
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder=""
                autoComplete="current-password"
                className="w-full h-10 pl-9 pr-10 bg-white border border-slate-300 rounded-md text-xs text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 shadow-xs transition-[color,box-shadow]"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2.5 top-2.5 p-1 text-slate-400 hover:text-slate-700 transition-colors"
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full h-10 bg-blue-900 hover:bg-blue-800 text-white text-xs font-semibold rounded-md shadow-xs transition-colors flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
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

        <div className="pt-2 border-t border-slate-100 text-center">
          <p className="text-[11px] text-slate-500 font-mono">
            Authorized security operators only &mdash; all sessions are cryptographically audited
          </p>
        </div>
      </div>
  );
}
