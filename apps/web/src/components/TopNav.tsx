"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  Cpu,
  User,
  LogOut,
  ChevronRight,
  Layers,
  Clock,
  Lock,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";
import { getUnlockedStep } from "@/components/EngagementStepper";

export const TopNav: React.FC = () => {
  const pathname = usePathname();
  const { currentProject, token, currentUser, logout } = useProject();
  const [workflowStatus, setWorkflowStatus] = useState<string>("IDLE");
  const [activeAgentsCount, setActiveAgentsCount] = useState<number>(0);

  // Dual Clock State
  const [time, setTime] = useState<{ utc: string; local: string; tzLabel: string }>({
    utc: "",
    local: "",
    tzLabel: "Local",
  });

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const utc = now.toISOString().slice(11, 19) + " UTC";
      const local = now.toLocaleTimeString([], { hour12: false });
      let tzLabel = "Local";
      try {
        const tzName = Intl.DateTimeFormat().resolvedOptions().timeZone || "";
        if (
          tzName.includes("Jakarta") ||
          tzName.includes("Asia/Pontianak") ||
          tzName.includes("Asia/Bangkok") ||
          tzName.includes("WIB")
        ) {
          tzLabel = "WIB";
        } else if (
          tzName.includes("Makassar") ||
          tzName.includes("Singapore") ||
          tzName.includes("Kuala_Lumpur") ||
          tzName.includes("WITA")
        ) {
          tzLabel = "WITA";
        } else if (tzName.includes("Jayapura") || tzName.includes("WIT")) {
          tzLabel = "WIT";
        } else {
          const parts = tzName.split("/");
          tzLabel = parts[parts.length - 1].replace(/_/g, " ") || "Local";
        }
      } catch {
        tzLabel = "Local";
      }
      setTime({ utc, local, tzLabel });
    };

    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

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

  if (pathname === "/login") {
    return null;
  }

  return (
    <header className="h-14 border-b border-slate-200 bg-white px-4 flex items-center justify-between select-none sticky top-0 z-50 shadow-xs">
      {/* Brand Identity & Hierarchical Engagement Breadcrumb */}
      <div className="flex items-center gap-4 sm:gap-5">
        <Link href="/projects" className="flex items-center gap-2.5 group" title="Return to Engagements Directory">
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
            <p className="text-[10px] text-slate-500 font-mono -mt-0.5">Autonomous Security Platform</p>
          </div>
        </Link>

        {/* Clean Hierarchical Breadcrumb Navigation */}
        <div className="flex items-center gap-2 pl-3 sm:pl-4 border-l border-slate-200">
          <Link
            href="/projects"
            className={`text-xs font-medium flex items-center gap-1.5 transition-colors ${
              pathname === "/projects"
                ? "text-slate-900 font-bold"
                : "text-slate-500 hover:text-blue-900"
            }`}
            title="View all authorized engagements"
          >
            <Layers className="h-3.5 w-3.5 text-slate-400" />
            <span>Engagements</span>
          </Link>

          {pathname !== "/projects" && (
            <>
              <ChevronRight className="h-3 w-3 text-slate-300" />

              {currentProject ? (
                <div className="flex items-center gap-2">
                  <Link
                    href="/"
                    className="text-xs text-slate-900 hover:text-blue-900 font-semibold max-w-[200px] truncate transition-colors"
                    title={`${currentProject.name} - View Executive Telemetry Overview`}
                  >
                    {currentProject.name}
                  </Link>
                  {currentProject.target_domains?.[0] && (
                    <span className="text-[11px] font-mono text-slate-600 bg-slate-100 border border-slate-200 px-2 py-0.5 rounded hidden sm:inline-block">
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
            </>
          )}
        </div>
      </div>

      {/* Center: Synchronized Dual SOC Monospace Clock (UTC & Local Time) */}
      <div className="hidden md:flex items-center gap-2 px-3 py-1 bg-slate-50 border border-slate-200 rounded-md font-mono text-xs shadow-2xs">
        <Clock className="h-3.5 w-3.5 text-blue-700 shrink-0" />
        <span className="font-bold text-slate-800">{time.utc || "--:--:-- UTC"}</span>
        <span className="text-slate-300">|</span>
        <span className="text-slate-700 font-medium">
          {time.local || "--:--:--"}{" "}
          <span className="text-[10px] text-slate-500 font-semibold">{time.tzLabel}</span>
        </span>
      </div>

      {/* Right Controls: Audit Trail, Agent Status & User Profile */}
      <div className="flex items-center gap-2.5 sm:gap-3">
        {/* Audit Hash Chain Shortcut */}
        <Link
          href="/audit-logs"
          className="p-1.5 rounded-md hover:bg-slate-100 text-slate-500 hover:text-slate-900 border border-transparent hover:border-slate-200 transition-colors"
          title="Inspect Cryptographic Audit Hash Chain"
        >
          <Lock className="h-3.5 w-3.5 text-slate-600" />
        </Link>

        {/* Multi-Agent DAG Status Pill (State-Aware Gated) */}
        {pathname !== "/projects" && currentProject && (() => {
          const isAgentsUnlocked =
            getUnlockedStep(currentProject) >= 4 ||
            currentProject.status === "COMPLETED" ||
            workflowStatus === "RUNNING";

          if (!isAgentsUnlocked) {
            return (
              <div
                className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-50 border border-slate-200 rounded opacity-60 cursor-not-allowed select-none"
                title="Multi-Agent DAG is locked until Step 1 (Scope) and Step 3 (WSTG Plan) are completed"
              >
                <Lock className="h-3 w-3 text-slate-400" />
                <span className="text-xs font-mono text-slate-500">
                  Agents: <strong className="font-semibold text-slate-600">STANDBY</strong>
                </span>
              </div>
            );
          }

          return (
            <Link
              href="/agents"
              className={`flex items-center gap-2 px-2.5 py-1 rounded transition-colors border ${
                workflowStatus === "RUNNING"
                  ? "bg-amber-50 border-amber-200 text-amber-900 shadow-2xs hover:bg-amber-100"
                  : "bg-slate-50 hover:bg-slate-100 border-slate-200 text-slate-700"
              }`}
              title="Inspect Multi-Agent Execution Telemetry (Step 4)"
            >
              <Cpu
                className={`h-3.5 w-3.5 ${
                  workflowStatus === "RUNNING" ? "text-amber-600 animate-spin" : "text-blue-700"
                }`}
              />
              <span className="text-xs font-mono">
                Agents:{" "}
                <strong className={workflowStatus === "RUNNING" ? "text-amber-800 font-bold" : "text-slate-900"}>
                  {workflowStatus}
                </strong>
                {activeAgentsCount > 0 && <span className="text-slate-500 font-normal"> ({activeAgentsCount})</span>}
              </span>
            </Link>
          );
        })()}

        {/* User Account / Logout */}
        <div className="flex items-center gap-2 pl-2.5 sm:pl-3 border-l border-slate-200">
          {token && currentUser ? (
            <>
              <div className="flex items-center gap-2 text-xs text-slate-800 font-medium">
                <div className="h-6 w-6 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-600">
                  <User className="h-3.5 w-3.5" />
                </div>
                <div className="hidden sm:flex flex-col text-left leading-tight">
                  <span className="font-semibold text-slate-900 max-w-[120px] truncate font-mono">
                    {currentUser.full_name || currentUser.email || "ADMIN"}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono font-semibold">
                    {currentUser.role || "ADMIN"}
                  </span>
                </div>
              </div>
              <button
                onClick={logout}
                title="Sign out of Pentesa"
                className="p-1.5 hover:bg-slate-100 rounded text-slate-400 hover:text-rose-600 transition-colors ml-1 cursor-pointer"
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
