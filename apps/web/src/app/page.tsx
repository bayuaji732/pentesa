"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  AlertOctagon,
  AlertTriangle,
  AlertCircle,
  Info,
  Play,
  CheckCircle2,
  Cpu,
  Layers,
  ArrowRight,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export default function DashboardPage() {
  const { currentProject, loading: projectLoading } = useProject();
  const [findings, setFindings] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<any>(null);
  const [workflow, setWorkflow] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [startingWorkflow, setStartingWorkflow] = useState(false);

  const loadData = async (isPoll = false) => {
    if (!currentProject) {
      setLoading(false);
      return;
    }
    if (!isPoll) setLoading(true);
    try {
      const [fList, cov, wf] = await Promise.allSettled([
        api.listFindings(currentProject.id),
        api.getWSTGCoverage(currentProject.id),
        api.getWorkflowStatus(currentProject.id),
      ]);

      if (fList.status === "fulfilled") {
        const val: any = fList.value;
        setFindings(Array.isArray(val) ? val : Array.isArray(val?.items) ? val.items : []);
      }
      if (cov.status === "fulfilled") setCoverage(cov.value);
      if (wf.status === "fulfilled") setWorkflow(wf.value);
    } catch (err) {
      console.error("Dashboard data load error", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData(false);
  }, [currentProject]);

  useEffect(() => {
    if (!currentProject || workflow?.status !== "RUNNING") return;
    const timer = setInterval(() => {
      loadData(true);
    }, 2500);
    return () => clearInterval(timer);
  }, [currentProject, workflow?.status]);

  const handleStartAutonomousScan = async () => {
    if (!currentProject) return;
    setStartingWorkflow(true);
    try {
      const started = await api.startWorkflow(currentProject.id, true, "QUICK", true);
      setWorkflow(started);
      await loadData();
    } catch (err: any) {
      alert(`Workflow launch failed: ${err.message}`);
    } finally {
      setStartingWorkflow(false);
    }
  };

  // Severity counts
  const sevCounts = {
    Critical: findings.filter((f) => f.severity === "Critical").length,
    High: findings.filter((f) => f.severity === "High").length,
    Medium: findings.filter((f) => f.severity === "Medium").length,
    Low: findings.filter((f) => f.severity === "Low").length,
    Informational: findings.filter((f) => f.severity === "Informational").length,
  };

  if (projectLoading || loading) {
    return (
      <div className="h-full flex items-center justify-center text-xs font-mono text-slate-400 gap-2">
        <RefreshCw className="h-4 w-4 animate-spin text-red-500" />
        Loading SOC telemetry...
      </div>
    );
  }

  if (!currentProject) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center space-y-4 max-w-md mx-auto">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-full text-slate-400">
          <Layers className="h-8 w-8" />
        </div>
        <h2 className="text-lg font-bold text-slate-200">No Engagement Project Selected</h2>
        <p className="text-xs text-slate-400">
          Please select or onboard an authorized penetration testing engagement to view telemetry and launch autonomous multi-agent testing.
        </p>
        <Link
          href="/projects"
          className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-medium flex items-center gap-1.5 transition-colors"
        >
          <span>Onboard New Project</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Target Engagement Banner */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-5 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <h1 className="text-lg font-bold text-slate-100">{currentProject.name}</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
              ACTIVE ENGAGEMENT
            </span>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">{currentProject.description}</p>
          <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] font-mono text-slate-400">
            <span>Primary Target: <strong className="text-slate-200">{currentProject.target_domains?.[0] || "N/A"}</strong></span>
            <span>CIDRs: <strong className="text-slate-200">{currentProject.allowed_cidrs?.join(", ") || "None"}</strong></span>
            <span>RoE Window: <strong className="text-slate-200">{new Date(currentProject.authorization_end).toLocaleDateString()}</strong></span>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleStartAutonomousScan}
            disabled={startingWorkflow || workflow?.status === "RUNNING"}
            className="px-3.5 py-2 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold flex items-center gap-2 shadow-lg shadow-red-950/40 transition-all disabled:opacity-50"
          >
            {startingWorkflow ? (
              <>
                <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Dispatching Agents...
              </>
            ) : workflow?.status === "RUNNING" ? (
              <>
                <Cpu className="h-3.5 w-3.5 animate-spin text-cyan-200" />
                Autonomous Agents Active
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" />
                Launch Multi-Agent Assessment
              </>
            )}
          </button>
          <Link
            href="/reports"
            className="px-3.5 py-2 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded text-xs font-medium transition-colors"
          >
            View PTES Reports
          </Link>
        </div>
      </div>

      {/* Severity KPI Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {/* Critical */}
        <div className="bg-surface-base border border-red-900/60 rounded-lg p-3.5 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-red-400 font-mono">
            <span className="flex items-center gap-1.5 font-bold">
              <AlertOctagon className="h-3.5 w-3.5" /> CRITICAL
            </span>
            <span className="text-[10px] text-red-500">CVSS 9.0-10</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-red-400">{sevCounts.Critical}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">RCE, SQLi, Auth Bypass</div>
        </div>

        {/* High */}
        <div className="bg-surface-base border border-orange-900/60 rounded-lg p-3.5 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-orange-400 font-mono">
            <span className="flex items-center gap-1.5 font-bold">
              <AlertTriangle className="h-3.5 w-3.5" /> HIGH
            </span>
            <span className="text-[10px] text-orange-500">CVSS 7.0-8.9</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-orange-400">{sevCounts.High}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">IDOR, SSRF, Stored XSS</div>
        </div>

        {/* Medium */}
        <div className="bg-surface-base border border-amber-900/60 rounded-lg p-3.5 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-amber-400 font-mono">
            <span className="flex items-center gap-1.5 font-bold">
              <AlertCircle className="h-3.5 w-3.5" /> MEDIUM
            </span>
            <span className="text-[10px] text-amber-500">CVSS 4.0-6.9</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-400">{sevCounts.Medium}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">CSRF, Reflected XSS</div>
        </div>

        {/* Low */}
        <div className="bg-surface-base border border-blue-900/60 rounded-lg p-3.5 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-blue-400 font-mono">
            <span className="flex items-center gap-1.5 font-bold">
              <Info className="h-3.5 w-3.5" /> LOW
            </span>
            <span className="text-[10px] text-blue-500">CVSS 0.1-3.9</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-blue-400">{sevCounts.Low}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Headers, Clickjacking</div>
        </div>

        {/* Informational */}
        <div className="bg-surface-base border border-slate-800 rounded-lg p-3.5 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span className="flex items-center gap-1.5 font-bold">INFO</span>
            <span className="text-[10px] text-slate-500">CVSS 0.0</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-200">{sevCounts.Informational}</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Fingerprints, Banners</div>
        </div>
      </div>

      {/* Main Grid: Coverage & AI Agent DAG */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* WSTG Coverage Matrix Card */}
        <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-slate-200">OWASP WSTG v4.2 Coverage</h3>
            </div>
            <Link
              href="/wstg"
              className="text-xs text-slate-400 hover:text-red-400 font-mono flex items-center gap-1"
            >
              Matrix Explorer <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-slate-400">Total Mathematical Coverage</span>
              <span className="text-emerald-400 font-bold">{coverage?.overall_coverage_pct || 0}%</span>
            </div>
            <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
              <div
                className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                style={{ width: `${coverage?.overall_coverage_pct || 0}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-4 gap-2 pt-2 border-t border-slate-800/80 text-center text-xs font-mono">
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[10px]">Passed</div>
              <div className="text-emerald-400 font-bold text-sm">{coverage?.passed_count || 0}</div>
            </div>
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[10px]">Failed</div>
              <div className="text-red-400 font-bold text-sm">{coverage?.failed_count || 0}</div>
            </div>
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[10px]">Testing</div>
              <div className="text-cyan-400 font-bold text-sm">{coverage?.running_count || 0}</div>
            </div>
            <div className="p-2 bg-slate-900/60 rounded border border-slate-800">
              <div className="text-slate-400 text-[10px]">Planned</div>
              <div className="text-slate-300 font-bold text-sm">{coverage?.planned_count || 0}</div>
            </div>
          </div>
        </div>

        {/* Multi-Agent DAG Status Card */}
        <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Hierarchical Multi-Agent DAG</h3>
            </div>
            <Link
              href="/agents"
              className="text-xs text-slate-400 hover:text-cyan-400 font-mono flex items-center gap-1"
            >
              Live Telemetry <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Current Workflow Phase:</span>
              <span className="font-bold text-cyan-400">{workflow?.current_phase || "STANDBY"}</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Active Specialized Agents:</span>
              <span className="text-slate-200">{workflow?.active_agents?.length || 7} agents provisioned</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">Execution Status:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                  workflow?.status === "RUNNING"
                    ? "bg-cyan-950 text-cyan-400 border border-cyan-800"
                    : "bg-slate-800 text-slate-300"
                }`}
              >
                {workflow?.status || "STANDBY / READY"}
              </span>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 space-y-1">
            <p><strong>Hierarchical Supervisor DAG:</strong></p>
            <p className="font-mono text-[10px] text-slate-500">
              Planner &rarr; Recon &rarr; WSTG Matrix &rarr; Vuln Scanner &rarr; Authz Matrix &rarr; Validation &rarr; Reporting
            </p>
          </div>
        </div>
      </div>

      {/* Recent Findings Quick Table */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-200">Recent Findings & Forensic Evidence</h3>
          <Link
            href="/findings"
            className="text-xs text-slate-400 hover:text-red-400 font-mono flex items-center gap-1"
          >
            All Findings ({findings.length}) <ArrowRight className="h-3 w-3" />
          </Link>
        </div>

        {findings.length === 0 ? (
          <div className="p-6 text-center text-xs font-mono text-slate-500">
            No confirmed findings recorded yet. Launch an autonomous assessment to discover vulnerabilities.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 font-mono uppercase text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Vulnerability Title</th>
                  <th className="py-2.5 px-3">WSTG / CWE</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {findings.slice(0, 5).map((f) => (
                  <tr key={f.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          f.severity === "Critical"
                            ? "bg-red-950 text-red-400 border-red-800"
                            : f.severity === "High"
                            ? "bg-orange-950 text-orange-400 border-orange-800"
                            : f.severity === "Medium"
                            ? "bg-amber-950 text-amber-400 border-amber-800"
                            : "bg-blue-950 text-blue-400 border-blue-800"
                        }`}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-sans font-medium text-slate-200">
                      {f.title}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {f.wstg_id || f.cwe_id || "OWASP Top 10"}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-[11px] text-slate-300 font-semibold">{f.status}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <Link
                        href={`/findings#${f.id}`}
                        className="text-red-400 hover:text-red-300 text-[11px] flex items-center gap-1"
                      >
                        Inspect <ExternalLink className="h-3 w-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

