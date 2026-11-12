"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldCheck,
  Plus,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/lib/ToastContext";
import { api } from "@/lib/api";
import { EngagementStepper } from "@/components/EngagementStepper";
import { StepFooterNav } from "@/components/StepFooterNav";

export default function ScopePage() {
  const { currentProject } = useProject();
  const { toast, confirmDialog } = useToast();
  const [rules, setRules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // New Rule Form State
  const [pattern, setPattern] = useState("");
  const [ruleType, setRuleType] = useState("EXACT_DOMAIN");
  const [targetType, setTargetType] = useState("IN_SCOPE");
  const [portRange, setPortRange] = useState("");
  const [isCritical, setIsCritical] = useState(false);
  const [notes, setNotes] = useState("");
  const [addingRule, setAddingRule] = useState(false);

  // Scope Checker State
  const [testUrl, setTestUrl] = useState("");
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
        port_range: portRange.trim() || undefined,
        is_critical: isCritical,
        notes: notes.trim() || undefined,
      });
      setPattern("");
      setPortRange("");
      setNotes("");
      await loadRules();
      toast.success("Scope boundary rule added successfully.");
    } catch (err: any) {
      toast.error(`Failed to add scope rule: ${err.message}`);
    } finally {
      setAddingRule(false);
    }
  };

  const handleDeleteRule = async (ruleId: string, rulePattern: string) => {
    if (!currentProject) return;
    const ok = await confirmDialog({
      title: "Remove Scope Boundary Rule",
      message: `Remove scope rule "${rulePattern}"? This will modify the enforced egress boundary filters.`,
      confirmText: "Remove Rule",
      isDestructive: true,
    });
    if (!ok) return;

    try {
      await api.deleteScopeRule(currentProject.id, ruleId);
      await loadRules();
      toast.success(`Scope rule "${rulePattern}" removed.`);
    } catch (err: any) {
      toast.error(`Failed to delete scope rule: ${err.message}`);
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
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center text-xs font-mono text-slate-500 bg-white border border-slate-200 rounded-xl shadow-xs">
          Please select an active engagement to configure scope boundaries.
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
            <ShieldCheck className="h-5 w-5 text-emerald-600" />
            Layer 1 & Layer 2 Scope Boundary Engine
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Enforces strict dot-boundary domain isolation, CIDR containment, and IMDS metadata protection.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadRules}
            disabled={loading}
            className="p-2 bg-white border border-slate-200 hover:bg-slate-50 rounded-md text-slate-600 hover:text-slate-900 transition-colors shadow-xs"
            title="Refresh scope rules"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-700" : ""}`} />
          </button>
        </div>
      </div>

      {/* Interactive Live Scope Tester */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Search className="h-4 w-4 text-blue-700" />
            <h3 className="text-sm font-bold text-slate-900">Interactive Scope Boundary Tester</h3>
          </div>
          <span className="text-[10px] font-mono font-medium text-slate-500 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded">
            Dual-Layer Mathematical Evaluation
          </span>
        </div>

        <form onSubmit={handleEvaluateScope} className="flex gap-2">
          <input
            type="text"
            required
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            placeholder="https://app.organization.com/path or http://169.254.169.254"
            className="flex-1 h-9 px-3 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 transition-all"
          />
          <button
            type="submit"
            disabled={evaluating}
            className="h-9 px-4 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-md transition-colors flex items-center gap-1.5 shrink-0 shadow-xs cursor-pointer disabled:opacity-50"
          >
            {evaluating ? "Evaluating..." : "Evaluate Scope"}
          </button>
        </form>

        {checkResult && (
          <div
            className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between ${
              checkResult.is_in_scope
                ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                : "bg-rose-50 border-rose-200 text-rose-800"
            }`}
          >
            <div className="flex items-center gap-2">
              {checkResult.is_in_scope ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-600 shrink-0" />
              ) : (
                <XCircle className="h-4 w-4 text-rose-600 shrink-0" />
              )}
              <span>
                <strong>{checkResult.is_in_scope ? "IN-SCOPE" : "OUT OF SCOPE / BLOCKED"}</strong>:{" "}
                {checkResult.reason || (checkResult.is_in_scope ? "Destination strictly complies with authorized rules" : "Destination violates engagement scope boundaries")}
              </span>
            </div>
            <span className="text-[10px] text-slate-500 font-semibold">Layer 1 Verified</span>
          </div>
        )}
      </div>

      {/* Add New Scope Rule Form */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3.5">
        <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Plus className="h-4 w-4 text-blue-900" />
          Add Authorized Boundary Rule
        </h3>

        <form onSubmit={handleAddRule} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-6 gap-3">
          <div className="space-y-1 md:col-span-2">
            <label className="text-[11px] font-semibold text-slate-700">Target Pattern *</label>
            <input
              type="text"
              required
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="app.organization.com, *.organization.com, /logout"
              className="w-full h-9 px-3 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-semibold text-slate-700">Rule Type</label>
            <select
              value={ruleType}
              onChange={(e) => setRuleType(e.target.value)}
              className="w-full h-9 px-2 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
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
            <label className="text-[11px] font-semibold text-slate-700">Disposition</label>
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="w-full h-9 px-2 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
            >
              <option value="IN_SCOPE">IN_SCOPE (Allow)</option>
              <option value="OUT_OF_SCOPE">OUT_OF_SCOPE (Block)</option>
            </select>
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-semibold text-slate-700">Port Range (Optional)</label>
            <input
              type="text"
              value={portRange}
              onChange={(e) => setPortRange(e.target.value)}
              placeholder="80,443 or 9000"
              className="w-full h-9 px-3 bg-white border border-slate-300 rounded-md text-xs font-mono text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
            />
          </div>

          <div className="flex items-end">
            <button
              type="submit"
              disabled={addingRule}
              className="w-full h-9 bg-blue-900 hover:bg-blue-800 text-white rounded-md text-xs font-semibold shadow-xs transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50 cursor-pointer"
            >
              <Plus className="h-3.5 w-3.5" />
              {addingRule ? "Adding..." : "Add Rule"}
            </button>
          </div>
        </form>
      </div>

      {/* Rules Inventory Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="p-3.5 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <h3 className="text-xs font-bold font-mono uppercase text-slate-700">
            Active Scope Rules ({rules.length})
          </h3>
          <span className="text-[10px] font-mono text-slate-500 font-semibold">Strictly Enforced on Egress</span>
        </div>

        {rules.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No scope rules configured. Add an exact domain or wildcard pattern above.
          </div>
        ) : (
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50/50 text-slate-600 text-[10px] uppercase border-b border-slate-200 font-bold tracking-wider">
              <tr>
                <th className="py-2.5 px-3.5">Type</th>
                <th className="py-2.5 px-3.5">Target Pattern</th>
                <th className="py-2.5 px-3.5">Disposition</th>
                <th className="py-2.5 px-3.5">Protocols / Ports</th>
                <th className="py-2.5 px-3.5">Critical Target</th>
                <th className="py-2.5 px-3.5">Notes</th>
                <th className="py-2.5 px-3.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {rules.map((r) => (
                <tr key={r.id} className="hover:bg-slate-50/70 transition-colors">
                  <td className="py-2.5 px-3.5 text-slate-700 font-semibold">{r.rule_type}</td>
                  <td className="py-2.5 px-3.5 text-slate-900 font-bold">{r.pattern}</td>
                  <td className="py-2.5 px-3.5">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold border ${
                        r.target_type === "IN_SCOPE"
                          ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                          : "bg-rose-50 text-rose-800 border-rose-200"
                      }`}
                    >
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          r.target_type === "IN_SCOPE" ? "bg-emerald-500" : "bg-rose-500"
                        }`}
                      />
                      {r.target_type}
                    </span>
                  </td>
                  <td className="py-2.5 px-3.5 text-slate-600 text-[11px]">
                    {r.protocol || "http,https"}:{r.port_range || "80,443"}
                  </td>
                  <td className="py-2.5 px-3.5">
                    {r.is_critical ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-800 border border-rose-200">
                        <span className="h-1.5 w-1.5 rounded-full bg-rose-600 animate-pulse" />
                        CRITICAL
                      </span>
                    ) : (
                      <span className="text-slate-500">Standard</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3.5 text-slate-500 text-[11px] truncate max-w-xs">
                    {r.notes || "—"}
                  </td>
                  <td className="py-2.5 px-3.5 text-right">
                    <button
                      onClick={() => handleDeleteRule(r.id, r.pattern)}
                      title="Delete scope rule"
                      className="p-1 rounded text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* 6-Phase Linear Bottom Navigation */}
      <StepFooterNav
        currentStep={1}
        nextStepPath="/discovery"
        nextStepLabel="Save & Continue to Attack Surface Recon"
        canAdvance={rules.length > 0 || (currentProject.target_domains?.length || 0) > 0}
        advanceTooltip="Please configure at least 1 in-scope target domain or boundary rule to proceed"
      />
    </div>
  );
}
