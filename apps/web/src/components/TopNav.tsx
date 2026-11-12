"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Shield, Cpu, User, LogOut, ChevronRight, Layers } from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export const TopNav: React.FC = () => {
  const { currentProject, token, logout } = useProject();
  const [workflowStatus, setWorkflowStatus] = useState<string>("IDLE");
  const [activeAgentsCount, setActiveAgentsCount] = useState<number>(0);
  const [currentUser, setCurrentUser] = useState<{ email?: string; full_name?: string; role?: string } | null>(null);

  useEffect(() => {
    if (!token) {
      setCurrentUser(null);
      return;
    }
    api
      .getCurrentUser()
      .then((user) => setCurrentUser(user))
      .catch(() => setCurrentUser(null));
  }, [token]);

  useEffect(() => {
    if (!currentProject) {
      setWorkflowStatus("IDLE");
      setActiveAgentsCount(0);
      return;
    }
    const fetchStatus = () => {
      api
        .getWorkflowStatus(currentProject.id)
        .then((res) => {
          setWorkflowStatus(res.status || "IDLE");
          setActiveAgentsCount(res.active_agents?.length || 0);
        })
        .catch(() => {
          setWorkflowStatus("STANDBY");
          setActiveAgentsCount(0);
        });
    };
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, [currentProject]);

  return (
    <header className="h-14 border-b border-slate-200 bg-white px-4 flex items-center justify-between select-none sticky top-0 z-50 shadow-xs">
      {/* Brand Identity & Hierarchical Project Breadcrumb */}
      <div className="flex items-center gap-5">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="h-8 w-8 rounded-lg bg-blue-900 border border-blue-800 flex items-center justify-center text-white shadow-xs group-hover:scale-105 transition-transform">
            <Shield className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold tracking-wider text-sm text-slate-900">PENTESA</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-blue-50 text-blue-900 border border-blue-200 font-semibold">
                SOC v1.0
              </span>
            </div>
            <p className="text-[10px] text-slate-500 font-mono -mt-0.5">Autonomous Pentest Engine</p>
          </div>
        </Link>

        {/* Clean Hierarchical Breadcrumb Navigation */}
        <div className="flex items-center gap-2 pl-4 border-l border-slate-200">
          <Link
            href="/projects"
            className="text-xs text-slate-500 hover:text-blue-900 font-medium flex items-center gap-1.5 transition-colors"
            title="View all engagement projects"
          >
            <Layers className="h-3.5 w-3.5 text-slate-400" />
            <span>Projects</span>
          </Link>

          <ChevronRight className="h-3 w-3 text-slate-300" />

          {currentProject ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-900 font-semibold max-w-[200px] truncate" title={currentProject.name}>
                {currentProject.name}
              </span>
              {currentProject.target_domains?.[0] && (
                <span className="text-[11px] font-mono text-slate-600 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded">
                  {currentProject.target_domains[0]}
                </span>
              )}
            </div>
          ) : (
            <Link
              href="/projects"
              className="text-xs text-blue-700 hover:text-blue-900 font-mono font-medium hover:underline flex items-center gap-1"
            >
              + Select Active Engagement
            </Link>
          )}
        </div>
      </div>

      {/* Center Scope Security Badge */}
      <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-emerald-50 border border-emerald-200 rounded-full shadow-xs">
        <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
        <span className="text-[11px] font-mono font-semibold text-emerald-800 tracking-wide">
          LAYER 1 & 2 SCOPE GUARD ENFORCED
        </span>
      </div>

      {/* Right Controls: Agent Status & User Profile */}
      <div className="flex items-center gap-3">
        {/* Multi-Agent DAG Status Pill */}
        <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-50 border border-slate-200 rounded">
          <Cpu className={`h-3.5 w-3.5 ${workflowStatus === "RUNNING" ? "text-amber-600 animate-spin" : "text-slate-500"}`} />
          <span className="text-xs font-mono text-slate-700">
            Agents: <strong className={workflowStatus === "RUNNING" ? "text-amber-700 font-bold" : "text-slate-900"}>{workflowStatus}</strong>
            {activeAgentsCount > 0 && <span className="text-slate-500"> ({activeAgentsCount})</span>}
          </span>
        </div>

        {/* User Account / Logout */}
        <div className="flex items-center gap-2 pl-3 border-l border-slate-200">
          {token ? (
            <>
              <div className="flex items-center gap-2 text-xs text-slate-800 font-medium">
                <div className="h-6 w-6 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600">
                  <User className="h-3.5 w-3.5" />
                </div>
                <div className="flex flex-col text-left leading-tight">
                  <span className="font-semibold text-slate-900 max-w-[120px] truncate">
                    {currentUser?.full_name || currentUser?.email || "Operator"}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {currentUser?.role || "Security Analyst"}
                  </span>
                </div>
              </div>
              <button
                onClick={logout}
                title="Sign out of Pentesa"
                className="p-1.5 hover:bg-slate-100 rounded text-slate-400 hover:text-rose-600 transition-colors ml-1"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </>
          ) : (
            <Link
              href="/login"
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-blue-900 hover:bg-blue-800 rounded shadow-xs transition-colors"
            >
              <User className="h-3.5 w-3.5" />
              <span>Sign In</span>
            </Link>
          )}
        </div>
      </div>
    </header>
  );
};
