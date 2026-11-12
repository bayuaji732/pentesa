"use client";

import React, { useEffect, useState } from "react";
import {
  CheckSquare,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  Clock,
  Ban,
  AlertCircle,
  HelpCircle,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

const WSTG_CATEGORIES = [
  { code: "ALL", name: "All Categories (106)" },
  { code: "WSTG-INFO", name: "Information Gathering" },
  { code: "WSTG-CONF", name: "Configuration Management" },
  { code: "WSTG-IDNT", name: "Identity Management" },
  { code: "WSTG-ATHN", name: "Authentication Testing" },
  { code: "WSTG-ATHZ", name: "Authorization Testing" },
  { code: "WSTG-SESS", name: "Session Management" },
  { code: "WSTG-INPV", name: "Input Validation (SQLi/XSS)" },
  { code: "WSTG-ERRH", name: "Error Handling" },
  { code: "WSTG-CRYP", name: "Cryptography" },
  { code: "WSTG-BUSL", name: "Business Logic" },
  { code: "WSTG-CLNT", name: "Client-Side Testing" },
  { code: "WSTG-APIT", name: "API Testing (REST/GraphQL)" },
];

const STATUS_FILTERS = [
  "ALL",
  "Planned",
  "Failed",
  "Passed",
  "Needs Manual Review",
  "Running",
  "Not Applicable",
  "Not Started",
  "Blocked",
  "Error",
];

function getStatusBadgeClass(status: string): string {
  switch (status) {
    case "Passed":
      return "bg-emerald-950 text-emerald-400 border-emerald-800";
    case "Failed":
      return "bg-red-950 text-red-400 border-red-800";
    case "Running":
      return "bg-cyan-950 text-cyan-400 border-cyan-800";
    case "Needs Manual Review":
      return "bg-amber-950 text-amber-300 border-amber-700";
    case "Planned":
      return "bg-sky-950 text-sky-300 border-sky-800";
    case "Not Applicable":
      return "bg-slate-900 text-slate-400 border-slate-700";
    case "Blocked":
    case "Error":
      return "bg-orange-950 text-orange-300 border-orange-800";
    default:
      return "bg-slate-800 text-slate-300 border-slate-700";
  }
}

export default function WSTGPage() {
  const { currentProject } = useProject();
  const [plan, setPlan] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [selectedStatus, setSelectedStatus] = useState<string>("ALL");
  const [recalculating, setRecalculating] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [recalcBanner, setRecalcBanner] = useState<string | null>(null);

  const loadData = async () => {
    if (!currentProject) return;
    setLoading(true);
    setErrorBanner(null);
    try {
      const [pList, cov] = await Promise.all([
        api.getWSTGPlan(currentProject.id),
        api.getWSTGCoverage(currentProject.id),
      ]);
      const planArr: any = pList;
      setPlan(Array.isArray(planArr) ? planArr : Array.isArray(planArr?.items) ? planArr.items : []);
      setCoverage(cov);
    } catch (err: any) {
      console.error("Failed to load WSTG plan", err);
      setErrorBanner(err?.message || "Failed to load OWASP WSTG matrix data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setRecalcBanner(null);
    setErrorBanner(null);
    loadData();
  }, [currentProject]);

  const handleRecalculate = async () => {
    if (!currentProject) return;
    setRecalculating(true);
    setErrorBanner(null);
    setRecalcBanner(null);
    try {
      const res = await api.recalculateWSTG(currentProject.id);
      if (res?.summary) {
        setRecalcBanner(res.summary);
      }
      await loadData();
    } catch (err: any) {
      setErrorBanner(`Recalculation error: ${err?.message || "Unknown API failure"}`);
    } finally {
      setRecalculating(false);
    }
  };

  const categoryCards = Object.values(coverage?.categories || {}) as Array<any>;

  const filteredPlan = plan.filter((item) => {
    const matchesCat =
      selectedCategory === "ALL" ||
      item.category_code === selectedCategory ||
      item.wstg_id.startsWith(selectedCategory);
    const matchesStatus = selectedStatus === "ALL" || item.status === selectedStatus;
    const matchesSearch =
      !search ||
      item.wstg_id.toLowerCase().includes(search.toLowerCase()) ||
      item.name.toLowerCase().includes(search.toLowerCase()) ||
      item.description?.toLowerCase().includes(search.toLowerCase()) ||
      item.justification?.toLowerCase().includes(search.toLowerCase());
    return matchesCat && matchesStatus && matchesSearch;
  });

  if (!currentProject) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-500">
        Please select a project to view WSTG v4.2 test matrix.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <CheckSquare className="h-5 w-5 text-emerald-400" />
            OWASP Web Security Testing Guide (WSTG v4.2)
          </h1>
          <p className="text-xs text-slate-400">
            Official 106-test comprehensive penetration testing matrix for{" "}
            <span className="text-slate-200 font-semibold">{currentProject.name}</span>.
          </p>
        </div>

        <button
          onClick={handleRecalculate}
          disabled={recalculating}
          className="px-3.5 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 shrink-0"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${recalculating ? "animate-spin" : ""}`} />
          {recalculating ? "Recalculating Matrix..." : "Recalculate Applicability"}
        </button>
      </div>

      {/* Dismissible Status Banners */}
      {errorBanner && (
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-red-800 bg-red-950/60 text-xs font-mono text-red-200">
          <span className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-red-400 shrink-0" />
            {errorBanner}
          </span>
          <button
            onClick={() => setErrorBanner(null)}
            className="text-red-400 hover:text-red-200 underline shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {recalcBanner && (
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-emerald-800 bg-emerald-950/40 text-xs font-mono text-emerald-200">
          <span className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            {recalcBanner}
          </span>
          <button
            onClick={() => setRecalcBanner(null)}
            className="text-emerald-400 hover:text-emerald-200 underline shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Coverage Status Bar */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-baseline gap-6">
            <div className="space-y-0.5">
              <div className="text-[11px] font-mono text-slate-400">
                Mathematical Assessment Coverage
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-400">
                {coverage?.overall_coverage_pct ?? 0}%
              </div>
            </div>
            <div className="space-y-0.5 border-l border-slate-800 pl-6">
              <div className="text-[11px] font-mono text-slate-400">Health Score</div>
              <div className="text-2xl font-bold font-mono text-cyan-400">
                {coverage?.testing_health_score ?? 0}%
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <CheckCircle2 className="h-3.5 w-3.5" /> Passed:{" "}
              <strong>{coverage?.passed_count ?? 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-red-400">
              <XCircle className="h-3.5 w-3.5" /> Failed:{" "}
              <strong>{coverage?.failed_count ?? 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-cyan-400">
              <Clock className="h-3.5 w-3.5" /> Running:{" "}
              <strong>{coverage?.running_count ?? 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-amber-300">
              <HelpCircle className="h-3.5 w-3.5" /> Review:{" "}
              <strong>{coverage?.needs_review_count ?? 0}</strong>
            </span>
            <span className="text-sky-300">
              Planned: <strong>{coverage?.planned_count ?? 0}</strong>
            </span>
            <span className="text-slate-400">
              N/A: <strong>{coverage?.not_applicable_count ?? 0}</strong>
            </span>
            {(coverage?.not_started_count ?? 0) > 0 && (
              <span className="text-slate-500">
                Pending: <strong>{coverage?.not_started_count ?? 0}</strong>
              </span>
            )}
          </div>
        </div>

        <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
          <div
            className="bg-emerald-500 h-full rounded-full transition-all duration-500"
            style={{ width: `${coverage?.overall_coverage_pct || 0}%` }}
          />
        </div>

        {/* 12-Category Breakdown Mini-Cards */}
        {categoryCards.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 pt-2 border-t border-slate-800/80">
            {categoryCards.map((cat) => {
              const isSelected = selectedCategory === cat.category_code;
              return (
                <button
                  key={cat.category_code}
                  type="button"
                  onClick={() =>
                    setSelectedCategory(isSelected ? "ALL" : cat.category_code)
                  }
                  className={`text-left p-2 rounded border transition-colors text-[11px] font-mono ${
                    isSelected
                      ? "bg-slate-800 border-red-500/70"
                      : "bg-slate-900/60 border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{cat.category_code}</span>
                    <span className="text-emerald-400">{cat.coverage_pct}%</span>
                  </div>
                  <div className="text-[10px] text-slate-400 truncate mt-0.5">
                    P:{cat.planned_count} N/A:{cat.not_applicable_count} F:{cat.failed_count}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-4 w-4 text-slate-500" />
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="h-8 px-2.5 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500"
          >
            {WSTG_CATEGORIES.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name}
              </option>
            ))}
          </select>

          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="h-8 px-2.5 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500"
          >
            {STATUS_FILTERS.map((st) => (
              <option key={st} value={st}>
                {st === "ALL" ? "All Statuses" : st}
              </option>
            ))}
          </select>

          <span className="text-[11px] font-mono text-slate-400 pl-1">
            Showing {filteredPlan.length} / {plan.length}
          </span>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-72">
          <Search className="h-3.5 w-3.5 text-slate-500 absolute left-2.5 top-2.5" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search WSTG ID, SQLi, XSS..."
            className="w-full h-8 pl-8 pr-3 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500"
          />
        </div>
      </div>

      {/* Test Matrix Table */}
      <div className="bg-surface-base border border-slate-800 rounded-lg overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">WSTG Test ID</th>
              <th className="py-2.5 px-3">Test Case Name</th>
              <th className="py-2.5 px-3">Category</th>
              <th className="py-2.5 px-3">Applicability</th>
              <th className="py-2.5 px-3">Execution Status</th>
              <th className="py-2.5 px-3">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {loading ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  Loading OWASP WSTG matrix...
                </td>
              </tr>
            ) : filteredPlan.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500">
                  No WSTG test cases match the current filters.
                </td>
              </tr>
            ) : (
              filteredPlan.map((item) => (
                <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2.5 px-3 font-bold text-red-400 whitespace-nowrap">
                    {item.wstg_id}
                  </td>
                  <td className="py-2.5 px-3 font-sans font-medium text-slate-200 max-w-md">
                    <div>{item.name}</div>
                    <div className="text-[11px] text-slate-400 font-mono line-clamp-1">
                      {item.description}
                    </div>
                    {item.justification && (
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5 line-clamp-2">
                        {item.justification}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">{item.category}</td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {item.status === "Not Started" ? (
                      <span className="text-slate-500 text-[11px]">Pending Calc</span>
                    ) : item.applicable ? (
                      <span className="text-emerald-400 font-semibold text-[11px]">
                        Applicable
                        {item.applicable_endpoints_count > 0
                          ? ` (${item.applicable_endpoints_count})`
                          : ""}
                      </span>
                    ) : (
                      <span className="text-slate-500 flex items-center gap-1 text-[11px]">
                        <Ban className="h-3 w-3" /> N/A
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadgeClass(
                        item.status
                      )}`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {item.findings_count > 0 ? (
                      <span className="font-bold text-red-400">{item.findings_count}</span>
                    ) : (
                      <span className="text-slate-500">0</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
