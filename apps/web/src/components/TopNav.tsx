"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Shield, ShieldAlert, Cpu, User, LogOut, ChevronDown, CheckCircle2 } from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export const TopNav: React.FC = () => {
  const { currentProject, projects, setCurrentProjectId, logout } = useProject();
  const [workflowStatus, setWorkflowStatus] = useState<string>("IDLE");
  const [activeAgentsCount, setActiveAgentsCount] = useState<number>(0);

  useEffect(() => {
    if (!currentProject) return;
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
  }, [currentProject]);

  return (
    <header className="h-14 border-b border-slate-800 bg-surface-base px-4 flex items-center justify-between select-none sticky top-0 z-50">
      {/* Brand Identity */}
      <div className="flex items-center gap-6">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="h-8 w-8 rounded-lg bg-red-950 border border-red-800 flex items-center justify-center text-red-400 group-hover:scale-105 transition-transform">
            <Shield className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold tracking-wider text-sm text-slate-100">PENTESA</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-red-950/80 text-red-400 border border-red-800/60">
                SOC v1.0
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono -mt-0.5">Autonomous Web Pentest Engine</p>
          </div>
        </Link>

        {/* Project Selector Dropdown */}
        <div className="flex items-center gap-2 pl-4 border-l border-slate-800">
          <span className="text-xs text-slate-400 font-medium">Target:</span>
          {projects.length > 0 ? (
            <div className="relative">
              <select
                value={currentProject?.id || ""}
                onChange={(e) => setCurrentProjectId(e.target.value)}
                className="h-8 pl-2.5 pr-8 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-red-500 cursor-pointer appearance-none"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.target_domains?.[0] || "No domain"})
                  </option>
                ))}
              </select>
              <ChevronDown className="h-3.5 w-3.5 text-slate-400 absolute right-2.5 top-2.5 pointer-events-none" />
            </div>
          ) : (
            <Link
              href="/projects"
              className="text-xs text-red-400 hover:text-red-300 font-mono flex items-center gap-1"
            >
              + Create Engagement Project
            </Link>
          )}
        </div>
      </div>

      {/* Center Scope Security Badge */}
      <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-slate-900/90 border border-emerald-900/60 rounded-full">
        <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
        <span className="text-[11px] font-mono font-medium text-emerald-400 tracking-wide">
          LAYER 1 & 2 SCOPE GUARD ENFORCED
        </span>
      </div>

      {/* Right Controls: Agent Status & User Profile */}
      <div className="flex items-center gap-4">
        {/* Multi-Agent DAG Status Pill */}
        <div className="flex items-center gap-2 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded">
          <Cpu className={`h-3.5 w-3.5 ${workflowStatus === "RUNNING" ? "text-cyan-400 animate-spin" : "text-slate-400"}`} />
          <span className="text-xs font-mono text-slate-300">
            Agents: <strong className={workflowStatus === "RUNNING" ? "text-cyan-400" : "text-slate-200"}>{workflowStatus}</strong>
            {activeAgentsCount > 0 && <span className="text-slate-400"> ({activeAgentsCount})</span>}
          </span>
        </div>

        {/* User Account / Logout */}
        <div className="flex items-center gap-2 pl-3 border-l border-slate-800">
          <div className="flex items-center gap-1.5 text-xs text-slate-300 font-medium">
            <User className="h-3.5 w-3.5 text-slate-400" />
            <span>Admin</span>
          </div>
          <button
            onClick={logout}
            title="Sign out of Pentesa"
            className="p-1.5 hover:bg-slate-800 rounded text-slate-400 hover:text-red-400 transition-colors"
          >
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
    </header>
  );
};

