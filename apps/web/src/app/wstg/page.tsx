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
import { EngagementStepper } from "@/components/EngagementStepper";
import { StepFooterNav } from "@/components/StepFooterNav";
import { EngagementStepGuard } from "@/components/EngagementStepGuard";

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
      return "bg-emerald-50 text-emerald-800 border-emerald-200";
    case "Failed":
      return "bg-rose-50 text-rose-800 border-rose-200";
    case "Running":
      return "bg-blue-50 text-blue-800 border-blue-200";
    case "Needs Manual Review":
      return "bg-amber-50 text-amber-800 border-amber-200";
    case "Planned":
      return "bg-slate-100 text-slate-800 border-slate-200";
    case "Not Applicable":
      return "bg-slate-50 text-slate-500 border-slate-200";
    case "Blocked":
    case "Error":
      return "bg-orange-50 text-orange-800 border-orange-200";
    default:
      return "bg-slate-100 text-slate-700 border-slate-200";
  }
}

function getStatusDotClass(status: string): string {
  switch (status) {
    case "Passed":
      return "bg-emerald-600";
    case "Failed":
      return "bg-rose-600 animate-pulse";
    case "Running":
      return "bg-blue-600";
    case "Needs Manual Review":
      return "bg-amber-600";
    case "Planned":
      return "bg-slate-500";
    case "Not Applicable":
      return "bg-slate-400";
    case "Blocked":
    case "Error":
      return "bg-orange-600";
    default:
      return "bg-slate-400";
  }
}

export default function WSTGPage() {
  return (
    <EngagementStepGuard requiredStep={3} stepTitle="OWASP WSTG Plan">
      <WSTGContent />
    </EngagementStepGuard>
  );
}

function WSTGContent() {
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
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center text-xs font-mono text-slate-500 bg-white border border-slate-200 rounded-xl shadow-xs">
          Please select an active engagement to view WSTG v4.2 test matrix.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <EngagementStepper />
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-lg font-bold text-slate-900 flex items-center gap-2">
            <CheckSquare className="h-5 w-5 text-blue-900" />
            OWASP Web Security Testing Guide (WSTG v4.2)
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Official 106-test comprehensive penetration testing matrix for{" "}
            <span className="text-slate-900 font-semibold">{currentProject.name}</span>.
          </p>
        </div>

        <button
          onClick={handleRecalculate}
          disabled={recalculating}
          className="px-4 py-2 bg-blue-900 hover:bg-blue-800 text-white rounded-md text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50 shrink-0 cursor-pointer"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${recalculating ? "animate-spin" : ""}`} />
          {recalculating ? "Recalculating Matrix..." : "Recalculate Applicability"}
        </button>
      </div>

      {/* Dismissible Status Banners */}
      {errorBanner && (
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-rose-200 bg-rose-50 text-xs font-mono text-rose-800 shadow-xs">
          <span className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-600 shrink-0" />
            {errorBanner}
          </span>
          <button
            onClick={() => setErrorBanner(null)}
            className="text-rose-700 hover:text-rose-900 underline shrink-0 font-medium"
          >
            Dismiss
          </button>
        </div>
      )}

      {recalcBanner && (
        <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-emerald-200 bg-emerald-50 text-xs font-mono text-emerald-800 shadow-xs">
          <span className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" />
            {recalcBanner}
          </span>
          <button
            onClick={() => setRecalcBanner(null)}
            className="text-emerald-700 hover:text-emerald-900 underline shrink-0 font-medium"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Coverage Status Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-baseline gap-6">
            <div className="space-y-0.5">
              <div className="text-[11px] font-mono text-slate-500 font-medium">
                Mathematical Assessment Coverage
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-700">
                {coverage?.overall_coverage_pct ?? 0}%
              </div>
            </div>
            <div className="space-y-0.5 border-l border-slate-200 pl-6">
              <div className="text-[11px] font-mono text-slate-500 font-medium">Health Score</div>
              <div className="text-2xl font-bold font-mono text-blue-900">
                {coverage?.testing_health_score ?? 0}%
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-emerald-700 font-semibold">
              <CheckCircle2 className="h-3.5 w-3.5" /> Passed:{" "}
              <strong>{coverage?.passed_count ?? 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-rose-700 font-semibold">
              <XCircle className="h-3.5 w-3.5" /> Failed:{" "}
              <strong>{coverage?.failed_count ?? 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-blue-700 font-semibold">
              <Clock className="h-3.5 w-3.5" /> Running:{" "}
              <strong>{coverage?.running_count ?? 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-amber-800 font-semibold">
              <HelpCircle className="h-3.5 w-3.5" /> Review:{" "}
              <strong>{coverage?.needs_review_count ?? 0}</strong>
            </span>
            <span className="text-slate-700 font-semibold">
              Planned: <strong>{coverage?.planned_count ?? 0}</strong>
            </span>
            <span className="text-slate-500">
              N/A: <strong>{coverage?.not_applicable_count ?? 0}</strong>
            </span>
            {(coverage?.not_started_count ?? 0) > 0 && (
              <span className="text-slate-400">
                Pending: <strong>{coverage?.not_started_count ?? 0}</strong>
              </span>
            )}
          </div>
        </div>

        <div className="w-full bg-slate-100 rounded-full h-2.5 overflow-hidden border border-slate-200">
          <div
            className="bg-blue-700 h-full rounded-full transition-all duration-500"
            style={{ width: `${coverage?.overall_coverage_pct || 0}%` }}
          />
        </div>

        {/* 12-Category Breakdown Mini-Cards */}
        {categoryCards.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 pt-2 border-t border-slate-100">
            {categoryCards.map((cat) => {
              const isSelected = selectedCategory === cat.category_code;
              return (
                <button
                  key={cat.category_code}
                  type="button"
                  onClick={() =>
                    setSelectedCategory(isSelected ? "ALL" : cat.category_code)
                  }
                  className={`text-left p-2.5 rounded-lg border transition-all text-[11px] font-mono shadow-xs ${
                    isSelected
                      ? "bg-blue-50 border-blue-600 ring-1 ring-blue-600/30"
                      : "bg-slate-50 border-slate-200 hover:border-slate-300 hover:bg-white"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-900">{cat.category_code}</span>
                    <span className="text-emerald-700 font-bold">{cat.coverage_pct}%</span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate mt-0.5">
                    P:{cat.planned_count} N/A:{cat.not_applicable_count} F:{cat.failed_count}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-white p-3 rounded-xl border border-slate-200 shadow-xs">
        <div className="flex flex-wrap items-center gap-2">
          <Filter className="h-4 w-4 text-slate-400" />
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="h-9 px-2.5 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
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
            className="h-9 px-2.5 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
          >
            {STATUS_FILTERS.map((st) => (
              <option key={st} value={st}>
                {st === "ALL" ? "All Statuses" : st}
              </option>
            ))}
          </select>

          <span className="text-[11px] font-mono text-slate-500 pl-1 font-medium">
            Showing {filteredPlan.length} / {plan.length}
          </span>
        </div>

        {/* Search */}
        <div className="relative w-full sm:w-72">
          <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-3 pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search WSTG ID, SQLi, XSS..."
            className="w-full h-9 pl-8 pr-3 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
          />
        </div>
      </div>

      {/* Test Matrix Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-x-auto shadow-xs">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-50/50 text-slate-600 text-[10px] uppercase border-b border-slate-200 font-bold tracking-wider">
            <tr>
              <th className="py-2.5 px-3.5">WSTG Test ID</th>
              <th className="py-2.5 px-3.5">Test Case Name</th>
              <th className="py-2.5 px-3.5">Category</th>
              <th className="py-2.5 px-3.5">Applicability</th>
              <th className="py-2.5 px-3.5">Execution Status</th>
              <th className="py-2.5 px-3.5 text-right">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
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
                <tr key={item.id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-2.5 px-3.5 font-bold text-blue-900 whitespace-nowrap">
                    {item.wstg_id}
                  </td>
                  <td className="py-2.5 px-3.5 font-sans font-semibold text-slate-900 max-w-md">
                    <div>{item.name}</div>
                    <div className="text-[11px] text-slate-500 font-mono line-clamp-1 font-normal">
                      {item.description}
                    </div>
                    {item.justification && (
                      <div className="text-[10px] text-slate-500 font-mono mt-0.5 line-clamp-2 font-normal">
                        {item.justification}
                      </div>
                    )}
                  </td>
                  <td className="py-2.5 px-3.5 text-slate-600 text-[11px]">{item.category}</td>
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    {item.status === "Not Started" ? (
                      <span className="text-slate-500 text-[11px]">Pending Calc</span>
                    ) : item.applicable ? (
                      <span className="text-emerald-700 font-bold text-[11px]">
                        Applicable
                        {item.applicable_endpoints_count > 0
                          ? ` (${item.applicable_endpoints_count})`
                          : ""}
                      </span>
                    ) : (
                      <span className="text-slate-400 flex items-center gap-1 text-[11px]">
                        <Ban className="h-3 w-3" /> N/A
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3.5 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadgeClass(
                        item.status
                      )}`}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${getStatusDotClass(item.status)}`} />
                      {item.status}
                    </span>
                  </td>
                  <td className="py-2.5 px-3.5 whitespace-nowrap text-right">
                    {item.findings_count > 0 ? (
                      <span className="font-bold text-rose-700">{item.findings_count}</span>
                    ) : (
                      <span className="text-slate-400">0</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* 6-Phase Linear Bottom Navigation */}
      <StepFooterNav
        currentStep={3}
        prevStepPath="/discovery"
        prevStepLabel="Attack Surface"
        nextStepPath="/agents"
        nextStepLabel="Approve Test Plan & Proceed to Agent DAG"
        canAdvance={plan.length > 0}
        advanceTooltip="Load or calculate WSTG test cases before advancing"
      />
    </div>
  );
}
