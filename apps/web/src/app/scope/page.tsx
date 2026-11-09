"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Plus,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export default function ScopePage() {
  const { currentProject } = useProject();
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // New Rule Form State
  const [pattern, setPattern] = useState("");
  const [ruleType, setRuleType] = useState("EXACT_DOMAIN");
  const [targetType, setTargetType] = useState("IN_SCOPE");
  const [isCritical, setIsCritical] = useState(false);
  const [notes, setNotes] = useState("");
  const [addingRule, setAddingRule] = useState(false);

  // Scope Checker State
  const [testUrl, setTestUrl] = useState("https://api.globalfin.local/api/v1/payments");
  const [checkResult, setCheckResult] = useState<any>(null);
  const [evaluating, setEvaluating] = useState(false);

  const loadRules = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const data = await api.listScopeRules(currentProject.id);
      setRules(data);
    } catch (err) {
      console.error("Failed to load scope rules", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, [currentProject]);

  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject || !pattern.trim()) return;
    setAddingRule(true);
    try {
      await api.addScopeRule(currentProject.id, {
        pattern: pattern.trim(),
        rule_type: ruleType,
        target_type: targetType,
        is_critical: isCritical,
        notes: notes.trim() || undefined,
      });
      setPattern("");
      setNotes("");
      await loadRules();
    } catch (err: any) {
      alert(`Failed to add scope rule: ${err.message}`);
    } finally {
      setAddingRule(false);
    }
  };

  const handleEvaluateScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject || !testUrl.trim()) return;
    setEvaluating(true);
    try {
      const res = await api.checkScope(currentProject.id, testUrl.trim());
      setCheckResult(res);
    } catch (err: any) {
      setCheckResult({ is_in_scope: false, reason: err.message });
    } finally {
      setEvaluating(false);
    }
  };

  if (!currentProject) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-500">
        Please select a project to configure scope boundaries.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-emerald-400" />
            Layer 1 & Layer 2 Scope Boundary Engine
          </h1>
          <p className="text-xs text-slate-400">
            Enforces strict dot-boundary domain isolation, CIDR containment, and IMDS metadata protection.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadRules}
            className="p-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Interactive Live Scope Tester */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">Interactive Scope Boundary Tester</h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">Dual-Layer Mathematical Evaluation</span>
        </div>

        <form onSubmit={handleEvaluateScope} className="flex gap-2">
          <input
            type="text"
            required
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            placeholder="https://target.com/path or http://169.254.169.254"
            className="flex-1 h-9 px-3 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500"
          />
          <button
            type="submit"
            disabled={evaluating}
            className="h-9 px-4 bg-slate-800 hover:bg-slate-700 border border-slate-600 text-slate-100 text-xs font-medium rounded transition-colors flex items-center gap-1.5 shrink-0"
          >
            {evaluating ? "Evaluating..." : "Evaluate Scope"}
          </button>
        </form>

        {checkResult && (
          <div
            className={`p-3 rounded border text-xs font-mono flex items-center justify-between ${
              checkResult.is_in_scope
                ? "bg-emerald-950/40 border-emerald-800 text-emerald-400"
                : "bg-red-950/40 border-red-800 text-red-400"
            }`}
          >
            <div className="flex items-center gap-2">
              {checkResult.is_in_scope ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              ) : (
                <XCircle className="h-4 w-4 text-red-400 shrink-0" />
              )}
              <span>
                <strong>{checkResult.is_in_scope ? "IN-SCOPE" : "OUT OF SCOPE / BLOCKED"}</strong>:{" "}
                {checkResult.reason || (checkResult.is_in_scope ? "Destination strictly complies with authorized rules" : "Destination violates engagement scope boundaries")}
              </span>
            </div>
            <span className="text-[10px] text-slate-400">Layer 1 Verified</span>
          </div>
        )}
      </div>

      {/* Add New Scope Rule Form */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Plus className="h-4 w-4 text-red-400" />
          Add Authorized Boundary Rule
        </h3>

        <form onSubmit={handleAddRule} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3">
          <div className="space-y-1 md:col-span-2">
            <label className="text-[11px] font-mono text-slate-400">Target Pattern</label>
            <input
              type="text"
              required
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="api.target.com, *.target.com, /logout"
              className="w-full h-8 px-2.5 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-100 focus:outline-none focus:border-red-500"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-mono text-slate-400">Rule Type</label>
            <select
              value={ruleType}
              onChange={(e) => setRuleType(e.target.value)}
              className="w-full h-8 px-2 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-100 focus:outline-none focus:border-red-500"
            >
              <option value="EXACT_DOMAIN">EXACT_DOMAIN</option>
              <option value="DOMAIN_WILDCARD">DOMAIN_WILDCARD (*.)</option>
              <option value="IP_CIDR">IP_CIDR (/24)</option>
              <option value="EXACT_IP">EXACT_IP</option>
              <option value="PATH_PREFIX">PATH_PREFIX</option>
              <option value="EXCLUDED_PATH">EXCLUDED_PATH</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-mono text-slate-400">Target Type</label>
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="w-full h-8 px-2 bg-slate-900 border border-slate-700 rounded text-xs font-mono text-slate-100 focus:outline-none focus:border-red-500"
            >
              <option value="IN_SCOPE">IN_SCOPE (Allow)</option>
              <option value="OUT_OF_SCOPE">OUT_OF_SCOPE (Block)</option>
            </select>
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={addingRule}
              className="w-full h-8 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              <Plus className="h-3.5 w-3.5" />
              {addingRule ? "Adding..." : "Add Rule"}
            </button>
          </div>
        </form>
      </div>

      {/* Rules Inventory Table */}
      <div className="bg-surface-base border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-bold font-mono uppercase text-slate-300">
            Active Scope Rules ({rules.length})
          </h3>
          <span className="text-[10px] font-mono text-slate-500">Strictly Enforced on Egress</span>
        </div>

        {rules.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No scope rules configured. Add an exact domain or wildcard pattern above.
          </div>
        ) : (
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Target Pattern</th>
                <th className="py-2.5 px-3">Disposition</th>
                <th className="py-2.5 px-3">Protocols / Ports</th>
                <th className="py-2.5 px-3">Critical Target</th>
                <th className="py-2.5 px-3">Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-2.5 px-3 text-slate-300 font-bold">{r.rule_type}</td>
                  <td className="py-2.5 px-3 text-slate-100 font-bold">{r.pattern}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        r.target_type === "IN_SCOPE"
                          ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                          : "bg-red-950 text-red-400 border-red-800"
                      }`}
                    >
                      {r.target_type}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                    {r.protocol || "http,https"}:{r.port_range || "80,443"}
                  </td>
                  <td className="py-2.5 px-3">
                    {r.is_critical ? (
                      <span className="text-red-400 font-bold flex items-center gap-1 text-[10px]">
                        <AlertTriangle className="h-3 w-3" /> CRITICAL
                      </span>
                    ) : (
                      <span className="text-slate-500">Standard</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 text-[11px] truncate max-w-xs">
                    {r.notes || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

