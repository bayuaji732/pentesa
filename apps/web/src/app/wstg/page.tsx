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
  ArrowRight,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export default function WSTGPage() {
  const { currentProject } = useProject();
  const [plan, setPlan] = useState<any[]>([]);
  const [coverage, setCoverage] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [recalculating, setRecalculating] = useState(false);

  const loadData = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const [pList, cov] = await Promise.all([
        api.getWSTGPlan(currentProject.id),
        api.getWSTGCoverage(currentProject.id),
      ]);
      const planArr: any = pList;
      setPlan(Array.isArray(planArr) ? planArr : Array.isArray(planArr?.items) ? planArr.items : []);
      setCoverage(cov);
    } catch (err) {
      console.error("Failed to load WSTG plan", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [currentProject]);

  const handleRecalculate = async () => {
    if (!currentProject) return;
    setRecalculating(true);
    try {
      await api.recalculateWSTG(currentProject.id);
      await loadData();
    } catch (err: any) {
      alert(`Recalculation error: ${err.message}`);
    } finally {
      setRecalculating(false);
    }
  };

  const categories = [
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
    { code: "WSTG-CLNT", name: "Client-side Testing" },
  ];

  const filteredPlan = plan.filter((item) => {
    const matchesCat =
      selectedCategory === "ALL" ||
      item.category_code === selectedCategory ||
      item.wstg_id.startsWith(selectedCategory);
    const matchesSearch =
      !search ||
      item.wstg_id.toLowerCase().includes(search.toLowerCase()) ||
      item.name.toLowerCase().includes(search.toLowerCase()) ||
      item.description?.toLowerCase().includes(search.toLowerCase());
    return matchesCat && matchesSearch;
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
            Official 106-test comprehensive penetration testing matrix with automated applicability engine.
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

      {/* Coverage Status Bar */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="space-y-1">
            <div className="text-xs font-mono text-slate-400">
              Mathematical Assessment Coverage Progress
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-400">
              {coverage?.overall_coverage_pct || 0}%
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <CheckCircle2 className="h-4 w-4" /> Passed: <strong>{coverage?.passed_count || 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-red-400">
              <XCircle className="h-4 w-4" /> Failed: <strong>{coverage?.failed_count || 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-cyan-400">
              <Clock className="h-4 w-4" /> Testing: <strong>{coverage?.in_progress_count || 0}</strong>
            </span>
            <span className="flex items-center gap-1.5 text-slate-400">
              Planned: <strong>{coverage?.planned_count || 0}</strong>
            </span>
          </div>
        </div>

        <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
          <div
            className="bg-emerald-500 h-full rounded-full transition-all duration-500"
            style={{ width: `${coverage?.overall_coverage_pct || 0}%` }}
          />
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        {/* Category Dropdown */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-slate-500" />
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="h-8 px-2.5 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500"
          >
            {categories.map((c) => (
              <option key={c.code} value={c.code}>
                {c.name}
              </option>
            ))}
          </select>
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
      <div className="bg-surface-base border border-slate-800 rounded-lg overflow-hidden">
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
            {filteredPlan.map((item) => (
              <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-2.5 px-3 font-bold text-red-400">{item.wstg_id}</td>
                <td className="py-2.5 px-3 font-sans font-medium text-slate-200 max-w-md">
                  <div>{item.name}</div>
                  <div className="text-[11px] text-slate-400 font-mono line-clamp-1">
                    {item.description}
                  </div>
                </td>
                <td className="py-2.5 px-3 text-slate-400 text-[11px]">{item.category}</td>
                <td className="py-2.5 px-3">
                  {item.applicable ? (
                    <span className="text-emerald-400 font-semibold text-[11px]">Applicable</span>
                  ) : (
                    <span className="text-slate-500 flex items-center gap-1 text-[11px]">
                      <Ban className="h-3 w-3" /> N/A
                    </span>
                  )}
                </td>
                <td className="py-2.5 px-3">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      item.status === "Passed"
                        ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                        : item.status === "Failed"
                        ? "bg-red-950 text-red-400 border-red-800"
                        : item.status === "Testing"
                        ? "bg-cyan-950 text-cyan-400 border-cyan-800"
                        : "bg-slate-800 text-slate-300 border-slate-700"
                    }`}
                  >
                    {item.status || "Planned"}
                  </span>
                </td>
                <td className="py-2.5 px-3">
                  {item.findings_count > 0 ? (
                    <span className="font-bold text-red-400">{item.findings_count}</span>
                  ) : (
                    <span className="text-slate-500">0</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

