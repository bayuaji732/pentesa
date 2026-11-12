"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
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
import { useToast } from "@/lib/ToastContext";
import { api } from "@/lib/api";

export default function DashboardPage() {
  const { currentProject, loading: projectLoading } = useProject();
  const { toast } = useToast();
  const [findings, setFindings] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<any>(null);
  const [workflow, setWorkflow] = useState<any>(null);
  const [loading, setLoading] = useState(true);

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
      <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500 gap-2">
        <RefreshCw className="h-4 w-4 animate-spin text-blue-700" />
        Loading SOC telemetry...
      </div>
    );
  }

  if (!currentProject) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center space-y-4 max-w-md mx-auto py-16">
        <div className="p-4 bg-white border border-slate-200 rounded-full text-slate-500 shadow-sm">
          <Layers className="h-8 w-8 text-blue-900" />
        </div>
        <h2 className="text-lg font-bold text-slate-900">No Engagement Selected</h2>
        <p className="text-xs text-slate-500 leading-relaxed">
          Please select or authorize a penetration testing engagement to view telemetry and lifecycle status.
        </p>
        <Link
          href="/projects"
          className="px-4 py-2 bg-blue-900 hover:bg-blue-800 text-white rounded-md text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors"
        >
          <span>Select or Authorize Engagement</span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Target Engagement Banner */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5">
            <h1 className="text-lg font-bold text-slate-900">{currentProject.name}</h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-800 border border-emerald-200">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              ACTIVE ENGAGEMENT
            </span>
          </div>
          <p className="text-xs text-slate-600 max-w-2xl leading-normal">{currentProject.description}</p>
          <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] font-mono text-slate-500">
            <span>Primary Target: <strong className="text-slate-800">{currentProject.target_domains?.[0] || "N/A"}</strong></span>
            <span>CIDRs: <strong className="text-slate-800">{currentProject.allowed_cidrs?.join(", ") || "None"}</strong></span>
            <span>RoE Window: <strong className="text-slate-800">{new Date(currentProject.authorization_end).toLocaleDateString()}</strong></span>
          </div>
        </div>

        {/* Guided Lifecycle Actions */}
        <div className="flex items-center gap-2.5 shrink-0">
          {workflow?.status === "RUNNING" ? (
            <Link
              href="/agents"
              className="px-4 py-2 bg-amber-600 hover:bg-amber-700 text-white rounded-md text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors"
            >
              <Cpu className="h-3.5 w-3.5 animate-spin text-white" />
              <span>Agents Active ({workflow?.current_phase || "SCANNING"}) →</span>
            </Link>
          ) : (
            <Link
              href="/scope"
              className="px-4 py-2 bg-blue-900 hover:bg-blue-800 text-white rounded-md text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors cursor-pointer"
            >
              <span>Enter Guided Lifecycle (Step 1: Scope)</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          )}
          <Link
            href="/projects"
            className="px-3.5 py-2 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-md text-xs font-medium transition-colors shadow-xs"
          >
            All Engagements
          </Link>
        </div>
      </div>

      {/* Severity KPI Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3.5">
        {/* Critical */}
        <div className="bg-white border border-rose-200 rounded-xl p-4 shadow-xs relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-rose-800 font-mono font-bold">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-rose-600 animate-pulse" />
              <AlertOctagon className="h-3.5 w-3.5 text-rose-600" /> CRITICAL
            </span>
            <span className="text-[10px] text-rose-800 bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded font-normal">CVSS 9.0-10</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-rose-800">{sevCounts.Critical}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-medium">RCE, SQLi, Auth Bypass</div>
        </div>

        {/* High */}
        <div className="bg-white border border-orange-200 rounded-xl p-4 shadow-xs relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-orange-800 font-mono font-bold">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-orange-600" />
              <AlertTriangle className="h-3.5 w-3.5 text-orange-600" /> HIGH
            </span>
            <span className="text-[10px] text-orange-800 bg-orange-50 border border-orange-200 px-1.5 py-0.5 rounded font-normal">CVSS 7.0-8.9</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-orange-800">{sevCounts.High}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-medium">IDOR, SSRF, Stored XSS</div>
        </div>

        {/* Medium */}
        <div className="bg-white border border-amber-200 rounded-xl p-4 shadow-xs relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-amber-800 font-mono font-bold">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-amber-600" />
              <AlertCircle className="h-3.5 w-3.5 text-amber-600" /> MEDIUM
            </span>
            <span className="text-[10px] text-amber-800 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded font-normal">CVSS 4.0-6.9</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-amber-800">{sevCounts.Medium}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-medium">CSRF, Reflected XSS</div>
        </div>

        {/* Low */}
        <div className="bg-white border border-blue-200 rounded-xl p-4 shadow-xs relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-blue-800 font-mono font-bold">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-blue-600" />
              <Info className="h-3.5 w-3.5 text-blue-600" /> LOW
            </span>
            <span className="text-[10px] text-blue-800 bg-blue-50 border border-blue-200 px-1.5 py-0.5 rounded font-normal">CVSS 0.1-3.9</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-blue-800">{sevCounts.Low}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-medium">Headers, Clickjacking</div>
        </div>

        {/* Informational */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-700 font-mono font-bold">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-slate-500" />
              <Info className="h-3.5 w-3.5 text-slate-500" /> INFO
            </span>
            <span className="text-[10px] text-slate-600 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded font-normal">CVSS 0.0</span>
          </div>
          <div className="mt-2 text-2xl font-bold font-mono text-slate-800">{sevCounts.Informational}</div>
          <div className="text-[11px] text-slate-500 mt-1 font-medium">Fingerprints, Banners</div>
        </div>
      </div>

      {/* Main Grid: Coverage & AI Agent DAG */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* WSTG Coverage Matrix Card */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
              <h3 className="text-sm font-bold text-slate-900">OWASP WSTG v4.2 Coverage</h3>
            </div>
            <Link
              href="/wstg"
              className="text-xs text-blue-700 hover:text-blue-900 font-medium flex items-center gap-1 transition-colors"
            >
              Matrix Explorer <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs font-mono">
              <span className="text-slate-600">Total Mathematical Coverage</span>
              <span className="text-emerald-700 font-bold">{coverage?.overall_coverage_pct || 0}%</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden border border-slate-200">
              <div
                className="bg-blue-700 h-full rounded-full transition-all duration-500"
                style={{ width: `${coverage?.overall_coverage_pct || 0}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-4 gap-2 pt-2 border-t border-slate-100 text-center text-xs font-mono">
            <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
              <div className="text-slate-500 text-[10px] font-medium">Passed</div>
              <div className="text-emerald-700 font-bold text-sm">{coverage?.passed_count || 0}</div>
            </div>
            <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
              <div className="text-slate-500 text-[10px] font-medium">Failed</div>
              <div className="text-rose-700 font-bold text-sm">{coverage?.failed_count || 0}</div>
            </div>
            <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
              <div className="text-slate-500 text-[10px] font-medium">Testing</div>
              <div className="text-blue-700 font-bold text-sm">{coverage?.running_count || 0}</div>
            </div>
            <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
              <div className="text-slate-500 text-[10px] font-medium">Planned</div>
              <div className="text-slate-800 font-bold text-sm">{coverage?.planned_count || 0}</div>
            </div>
          </div>
        </div>

        {/* Multi-Agent DAG Status Card */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-blue-700" />
              <h3 className="text-sm font-bold text-slate-900">Hierarchical Multi-Agent DAG</h3>
            </div>
            <Link
              href="/agents"
              className="text-xs text-blue-700 hover:text-blue-900 font-medium flex items-center gap-1 transition-colors"
            >
              Live Telemetry <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-lg space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-600">Current Workflow Phase:</span>
              <span className="font-bold text-blue-800">{workflow?.current_phase || "STANDBY"}</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-600">Active Specialized Agents:</span>
              <span className="text-slate-800 font-medium">{workflow?.active_agents?.length || 7} agents provisioned</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-600">Execution Status:</span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  workflow?.status === "RUNNING"
                    ? "bg-amber-100 text-amber-900 border-amber-300"
                    : "bg-slate-100 text-slate-700 border-slate-200"
                }`}
              >
                {workflow?.status || "STANDBY / READY"}
              </span>
            </div>
          </div>

          <div className="text-[11px] text-slate-600 space-y-1">
            <p className="font-medium text-slate-700">Hierarchical Supervisor DAG Pipeline:</p>
            <p className="font-mono text-[10px] text-slate-500">
              Planner &rarr; Recon &rarr; WSTG Matrix &rarr; Vuln Scanner &rarr; Authz Matrix &rarr; Validation &rarr; Reporting
            </p>
          </div>
        </div>
      </div>

      {/* Recent Findings Quick Table */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-900">Recent Findings & Forensic Evidence</h3>
          <Link
            href="/findings"
            className="text-xs text-blue-700 hover:text-blue-900 font-medium flex items-center gap-1 transition-colors"
          >
            All Findings ({findings.length}) <ArrowRight className="h-3 w-3" />
          </Link>
        </div>

        {findings.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No confirmed findings recorded yet. Launch an autonomous assessment to discover vulnerabilities.
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-slate-200">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 text-slate-600 font-mono uppercase text-[10px] border-b border-slate-200 font-bold tracking-wider">
                <tr>
                  <th className="py-2.5 px-3.5">Severity</th>
                  <th className="py-2.5 px-3.5">Vulnerability Title</th>
                  <th className="py-2.5 px-3.5">WSTG / CWE</th>
                  <th className="py-2.5 px-3.5">Status</th>
                  <th className="py-2.5 px-3.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono">
                {findings.slice(0, 5).map((f) => (
                  <tr key={f.id} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-2.5 px-3.5">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold border ${
                          f.severity === "Critical"
                            ? "bg-rose-50 text-rose-800 border-rose-200"
                            : f.severity === "High"
                            ? "bg-orange-50 text-orange-800 border-orange-200"
                            : f.severity === "Medium"
                            ? "bg-amber-50 text-amber-800 border-amber-200"
                            : "bg-blue-50 text-blue-800 border-blue-200"
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            f.severity === "Critical"
                              ? "bg-rose-600 animate-pulse"
                              : f.severity === "High"
                              ? "bg-orange-600"
                              : f.severity === "Medium"
                              ? "bg-amber-600"
                              : "bg-blue-600"
                          }`}
                        />
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 font-sans font-semibold text-slate-900">
                      {f.title}
                    </td>
                    <td className="py-2.5 px-3.5 text-slate-600 text-[11px]">
                      {f.wstg_id || f.cwe_id || "OWASP Top 10"}
                    </td>
                    <td className="py-2.5 px-3.5">
                      <span className="text-[11px] text-slate-700 font-semibold">{f.status}</span>
                    </td>
                    <td className="py-2.5 px-3.5 text-right">
                      <Link
                        href={`/findings#${f.id}`}
                        className="text-blue-700 hover:text-blue-900 text-[11px] font-medium inline-flex items-center gap-1"
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
