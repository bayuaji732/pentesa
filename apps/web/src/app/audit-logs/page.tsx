"use client";

import React, { useEffect, useRef, useState } from "react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";
import {
  Lock,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  Download,
  Clock,
  Database,
  ArrowRight,
  CheckCircle2,
  Layers,
} from "lucide-react";

export default function AuditLogsPage() {
  const { projects } = useProject();
  const [selectedProjectId, setSelectedProjectId] = useState<string>("ALL");
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Verification state
  const [verifying, setVerifying] = useState(false);
  const [chainStatus, setChainStatus] = useState<any | null>(null);
  const [lastVerified, setLastVerified] = useState<{
    at: string;
    durationMs: number;
    runCount: number;
  } | null>(null);
  const [justVerified, setJustVerified] = useState(false);
  const verifyTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Filters
  const [filterAction, setFilterAction] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedLog, setSelectedLog] = useState<any | null>(null);

  useEffect(() => {
    return () => {
      if (verifyTimerRef.current) clearTimeout(verifyTimerRef.current);
    };
  }, []);

  const fetchLogs = async (silent = false, projectIdToFetch?: string) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const pid = projectIdToFetch !== undefined ? projectIdToFetch : selectedProjectId;
      const data: any = await api.listAuditLogs(pid === "ALL" ? undefined : pid, 100);
      setLogs(Array.isArray(data) ? data : Array.isArray(data?.items) ? data.items : []);
    } catch (err: any) {
      console.error(err);
      if (!silent) {
        setError(err?.message || "Failed to retrieve audit log trail.");
      }
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const handleVerifyChain = async (manual = false, refreshLogs = manual) => {
    setVerifying(true);
    const t0 = typeof performance !== "undefined" ? performance.now() : Date.now();
    try {
      const [res] = await Promise.all([
        api.verifyAuditChain(),
        refreshLogs ? fetchLogs(true) : Promise.resolve(),
      ]);
      const nowMs = typeof performance !== "undefined" ? performance.now() : Date.now();
      const durationMs = Math.max(1, Math.round(nowMs - t0));
      setChainStatus(res);
      setLastVerified((prev) => ({
        at: new Date().toLocaleTimeString([], { hour12: false }),
        durationMs,
        runCount: (prev?.runCount ?? 0) + 1,
      }));
      if (manual) {
        setJustVerified(true);
        if (verifyTimerRef.current) clearTimeout(verifyTimerRef.current);
        verifyTimerRef.current = setTimeout(() => setJustVerified(false), 2500);
      }
    } catch (err: any) {
      const nowMs = typeof performance !== "undefined" ? performance.now() : Date.now();
      const durationMs = Math.max(1, Math.round(nowMs - t0));
      setChainStatus({
        is_valid: false,
        reason: err?.message || "Chain verification failed.",
      });
      setLastVerified((prev) => ({
        at: new Date().toLocaleTimeString([], { hour12: false }),
        durationMs,
        runCount: (prev?.runCount ?? 0) + 1,
      }));
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    fetchLogs(false, selectedProjectId);
    handleVerifyChain(false);
  }, [selectedProjectId]);

  const handleExportJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `pentesa_audit_chain_${new Date().toISOString()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredLogs = logs.filter((log) => {
    if (filterAction !== "ALL" && log.action !== filterAction) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchAction = log.action?.toLowerCase().includes(q);
      const matchResource = log.resource_type?.toLowerCase().includes(q);
      const matchHash = log.hash?.toLowerCase().includes(q);
      if (!matchAction && !matchResource && !matchHash) return false;
    }
    return true;
  });

  const getActionBadge = (action: string) => {
    const act = action?.toUpperCase() || "";
    if (act.includes("CREATE") || act.includes("START")) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-900 border border-blue-200">
          <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
          {action}
        </span>
      );
    }
    if (act.includes("REPORT") || act.includes("PUBLISH")) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-900 border border-emerald-200">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-600" />
          {action}
        </span>
      );
    }
    if (act.includes("FINDING") || act.includes("EXPLOIT")) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-900 border border-rose-200">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-600" />
          {action}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-800 border border-slate-200">
        <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
        {action}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900">Cryptographic Audit Trail</h1>
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-blue-50 text-blue-900 border border-blue-200">
              Platform Ledger
            </span>
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {logs.length} Blocks
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Tamper-evident, forward-secure SHA-256 Merkle hash chain recording every authentication event, scope modification, autonomous agent action, and finding.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            disabled={logs.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 border border-slate-200 shadow-xs transition-colors cursor-pointer"
          >
            <Download className="h-3.5 w-3.5 text-blue-900" />
            Export Signed Ledger
          </button>
          <button
            type="button"
            onClick={() => {
              fetchLogs(false);
              handleVerifyChain(true, false);
            }}
            disabled={loading || verifying}
            className="p-2 rounded-md bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 border border-slate-200 shadow-xs transition-colors"
            title="Refresh logs & chain"
          >
            <RefreshCw className={`h-4 w-4 ${loading || verifying ? "animate-spin text-blue-700" : ""}`} />
          </button>
        </div>
      </div>

      {/* Cryptographic Tamper Evidence Banner */}
      {chainStatus && (
        <div
          className={`p-5 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xs ${
            chainStatus.is_valid
              ? "bg-emerald-50 border-emerald-200 text-emerald-900"
              : "bg-rose-50 border-rose-200 text-rose-900"
          }`}
        >
          <div className="flex items-center gap-3.5">
            <div
              className={`p-2.5 rounded-full ${
                chainStatus.is_valid ? "bg-emerald-100 text-emerald-700" : "bg-rose-100 text-rose-700"
              }`}
            >
              {chainStatus.is_valid ? <ShieldCheck className="h-5 w-5" /> : <AlertTriangle className="h-5 w-5" />}
            </div>
            <div>
              <div className="text-xs font-bold font-mono uppercase tracking-wide">
                {chainStatus.is_valid
                  ? `● Cryptographic Hash Chain Valid: All ${chainStatus.total_records} entries verified`
                  : `✘ Integrity Hash Chain Mismatch Detected`}
              </div>
              <p className="text-[11px] text-slate-600 mt-0.5 leading-normal">
                {chainStatus.is_valid
                  ? "Every block is linked to previous block via SHA-256(prev_hash || payload). Zero ledger corruption or modification detected."
                  : chainStatus.reason || "Ledger inconsistency identified."}
              </p>
              {lastVerified && (
                <div className="text-[10px] font-mono text-slate-500 mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5">
                  <span>
                    Last verified: <strong className="text-slate-800">{lastVerified.at}</strong>
                  </span>
                  <span>
                    Duration: <strong className="text-slate-800">{lastVerified.durationMs} ms</strong>
                  </span>
                  <span>Check #{lastVerified.runCount}</span>
                  {chainStatus.last_hash && (
                    <span title={chainStatus.last_hash}>
                      Head: <span className="text-blue-900 font-bold">{chainStatus.last_hash.slice(0, 14)}...</span>
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 self-start sm:self-auto">
            {justVerified && chainStatus.is_valid && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold bg-emerald-100 text-emerald-800 border border-emerald-300">
                <CheckCircle2 className="h-3 w-3" />
                Verified
              </span>
            )}
            <button
              type="button"
              onClick={() => handleVerifyChain(true)}
              disabled={verifying}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 disabled:opacity-60 text-xs font-semibold border border-slate-300 text-slate-800 shadow-xs transition-colors cursor-pointer"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${verifying ? "animate-spin text-blue-700" : ""}`} />
              {verifying ? "Verifying..." : "Re-verify Chain"}
            </button>
          </div>
        </div>
      )}

      {/* Filtering Toolbar */}
      <div className="flex flex-col lg:flex-row gap-3 items-stretch lg:items-center justify-between bg-white p-3 rounded-xl border border-slate-200 shadow-xs">
        <div className="relative w-full lg:w-72">
          <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search action, resource, hash..."
            className="w-full bg-white pl-9 pr-3 py-1.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-mono transition-all"
          />
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Scope Selector: Global vs Project */}
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 font-semibold flex items-center gap-1">
              <Layers className="h-3 w-3 text-slate-400" /> Scope:
            </span>
            <select
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              className="bg-white text-xs text-slate-900 border border-slate-300 rounded-md px-2.5 py-1.5 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-sans max-w-[220px]"
            >
              <option value="ALL">All Engagements (Global)</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-[11px] font-mono text-slate-500 font-semibold flex items-center gap-1">
              <Filter className="h-3 w-3 text-slate-400" /> Action:
            </span>
            <select
              value={filterAction}
              onChange={(e) => setFilterAction(e.target.value)}
              className="bg-white text-xs text-slate-900 border border-slate-300 rounded-md px-3 py-1.5 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
            >
            <option value="ALL">All Actions</option>
            <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
            <option value="LOGIN_FAILED">LOGIN_FAILED</option>
            <option value="PROJECT_CREATED">PROJECT_CREATED</option>
            <option value="PROJECT_DELETED">PROJECT_DELETED</option>
            <option value="SCOPE_RULE_ADDED">SCOPE_RULE_ADDED</option>
            <option value="SCOPE_RULE_REMOVED">SCOPE_RULE_REMOVED</option>
            <option value="ATTACK_SURFACE_CRAWL_STARTED">ATTACK_SURFACE_CRAWL_STARTED</option>
            <option value="ATTACK_SURFACE_CRAWL_COMPLETED">ATTACK_SURFACE_CRAWL_COMPLETED</option>
            <option value="WSTG_PLAN_RECALCULATED">WSTG_PLAN_RECALCULATED</option>
            <option value="WORKFLOW_STARTED">WORKFLOW_STARTED</option>
            <option value="WORKFLOW_PAUSED">WORKFLOW_PAUSED</option>
            <option value="WORKFLOW_RESUMED">WORKFLOW_RESUMED</option>
            <option value="WORKFLOW_STOPPED">WORKFLOW_STOPPED</option>
            <option value="APPROVAL_APPROVED">APPROVAL_APPROVED</option>
            <option value="APPROVAL_REJECTED">APPROVAL_REJECTED</option>
            <option value="FINDING_CREATED">FINDING_CREATED</option>
            <option value="FINDING_STATUS_UPDATED">FINDING_STATUS_UPDATED</option>
            <option value="FINDING_FALSE_POSITIVE_REFUTED">FINDING_FALSE_POSITIVE_REFUTED</option>
            <option value="FINDING_RETEST_EXECUTED">FINDING_RETEST_EXECUTED</option>
            <option value="REPORT_GENERATED">REPORT_GENERATED</option>
          </select>
        </div>
      </div>
    </div>

      {/* Audit Log Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-50/50 border-b border-slate-200 text-[10px] font-mono text-slate-600 uppercase tracking-wider font-bold">
                <th className="py-2.5 px-4 font-semibold">Timestamp (UTC)</th>
                <th className="py-2.5 px-4 font-semibold">Action Verb</th>
                <th className="py-2.5 px-4 font-semibold">Resource Affected</th>
                <th className="py-2.5 px-4 font-semibold">Client IP</th>
                <th className="py-2.5 px-4 font-semibold">Merkle Hash Chain Link</th>
                <th className="py-2.5 px-4 font-semibold text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-slate-700">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-blue-700" />
                    Streaming cryptographic ledger...
                  </td>
                </tr>
              ) : filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    Zero audit log entries recorded matching filter.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-slate-50/70 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4 whitespace-nowrap text-slate-500">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3 text-slate-400" />
                        {new Date(log.created_at).toISOString().replace("T", " ").slice(0, 19)}
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">{getActionBadge(log.action)}</td>

                    <td className="py-3 px-4 whitespace-nowrap text-slate-800">
                      <span className="font-semibold text-slate-900">{log.resource_type}</span>
                      {log.resource_id && (
                        <span className="text-[10px] text-slate-500 ml-1.5">
                          ({log.resource_id.slice(0, 8)}...)
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap text-slate-600">
                      {log.ip_address || "N/A"}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1 text-[10px] text-slate-500">
                        <span className="text-slate-500 font-mono truncate max-w-[90px]" title={log.prev_hash}>
                          {log.prev_hash?.slice(0, 10)}...
                        </span>
                        <ArrowRight className="h-3 w-3 text-blue-600 shrink-0" />
                        <span className="text-blue-900 font-bold font-mono truncate max-w-[90px]" title={log.hash}>
                          {log.hash?.slice(0, 10)}...
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedLog(log);
                        }}
                        className="text-[11px] font-mono font-semibold text-blue-700 hover:text-blue-900 group-hover:underline cursor-pointer"
                      >
                        Inspect Payload →
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* JSON Delta Inspector Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Database className="h-5 w-5 text-blue-900" />
                <h3 className="text-base font-bold text-slate-900">Audit Ledger Block Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-slate-400 hover:text-slate-700 font-mono text-base p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 bg-slate-50 rounded-lg border border-slate-200 text-slate-800">
                <div>
                  <span className="text-slate-500 font-semibold">Action:</span> {selectedLog.action}
                </div>
                <div>
                  <span className="text-slate-500 font-semibold">Resource:</span> {selectedLog.resource_type}
                </div>
                <div>
                  <span className="text-slate-500 font-semibold">Timestamp:</span> {selectedLog.created_at}
                </div>
                <div>
                  <span className="text-slate-500 font-semibold">IP Address:</span> {selectedLog.ip_address || "N/A"}
                </div>
              </div>

              {/* Hash Chain Details */}
              <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 space-y-2 text-[11px]">
                <div>
                  <span className="text-slate-500 font-semibold">Previous Hash (H_prev):</span>
                  <div className="text-slate-600 break-all">{selectedLog.prev_hash}</div>
                </div>
                <div>
                  <span className="text-slate-500 font-semibold">Block SHA-256 Digest (H_curr):</span>
                  <div className="text-blue-900 font-bold break-all">{selectedLog.hash}</div>
                </div>
              </div>

              {/* Serialized Details Payload in Inset Dark Terminal */}
              <div>
                <span className="text-slate-700 font-semibold block mb-1">State Modification Delta (JSON Payload):</span>
                <pre className="p-3 rounded-lg bg-[#0b0f19] border border-slate-800 text-[11px] text-emerald-400 overflow-x-auto max-h-56">
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-2 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
