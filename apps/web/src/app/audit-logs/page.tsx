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
  Code2,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Database,
  ArrowRight,
  CheckCircle2,
} from "lucide-react";

export default function AuditLogsPage() {
  const { currentProject } = useProject();
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

  const fetchLogs = async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const data: any = await api.listAuditLogs(currentProject?.id, 100);
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
    fetchLogs(false);
    handleVerifyChain(false);
  }, [currentProject?.id]);

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
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-400 border border-cyan-800">
          {action}
        </span>
      );
    }
    if (act.includes("REPORT") || act.includes("PUBLISH")) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-400 border border-emerald-800">
          {action}
        </span>
      );
    }
    if (act.includes("FINDING") || act.includes("EXPLOIT")) {
      return (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950/80 text-red-400 border border-red-800">
          {action}
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
        {action}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-100">Cryptographic Audit Hash Chain</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {logs.length} Blocks
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tamper-evident, forward-secure SHA-256 Merkle chain recording every security action, rule change, and finding.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            disabled={logs.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition-colors"
          >
            <Download className="h-3.5 w-3.5 text-cyan-400" />
            Export Signed Ledger
          </button>
          <button
            type="button"
            onClick={() => {
              fetchLogs(false);
              handleVerifyChain(true, false);
            }}
            disabled={loading || verifying}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700"
            title="Refresh logs & chain"
          >
            <RefreshCw className={`h-4 w-4 ${loading || verifying ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Cryptographic Tamper Evidence Banner */}
      {chainStatus && (
        <div
          className={`p-4 rounded border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
            chainStatus.is_valid
              ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-300"
              : "bg-red-950/40 border-red-800/80 text-red-300"
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-full ${
                chainStatus.is_valid ? "bg-emerald-900/60 text-emerald-400" : "bg-red-900/60 text-red-400"
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
              <p className="text-[11px] text-slate-400 mt-0.5">
                {chainStatus.is_valid
                  ? "Every block is linked to previous block via SHA-256(prev_hash || payload). Zero ledger corruption or modification detected."
                  : chainStatus.reason || "Ledger inconsistency identified."}
              </p>
              {lastVerified && (
                <div className="text-[10px] font-mono text-slate-400/90 mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5">
                  <span>
                    Last verified: <span className="text-slate-200">{lastVerified.at}</span>
                  </span>
                  <span>
                    Duration: <span className="text-slate-200">{lastVerified.durationMs} ms</span>
                  </span>
                  <span>Check #{lastVerified.runCount}</span>
                  {chainStatus.last_hash && (
                    <span title={chainStatus.last_hash}>
                      Head: <span className="text-cyan-400">{chainStatus.last_hash.slice(0, 14)}...</span>
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0 self-start sm:self-auto">
            {justVerified && chainStatus.is_valid && (
              <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono bg-emerald-900/60 text-emerald-300 border border-emerald-700/70">
                <CheckCircle2 className="h-3 w-3" />
                Verified
              </span>
            )}
            <button
              type="button"
              onClick={() => handleVerifyChain(true)}
              disabled={verifying}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-black disabled:opacity-60 text-xs font-mono border border-slate-700 text-slate-200 transition-colors"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${verifying ? "animate-spin text-cyan-400" : ""}`} />
              {verifying ? "Verifying..." : "Re-verify Chain"}
            </button>
          </div>
        </div>
      )}

      {/* Filtering Toolbar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-surface-base p-3 rounded border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search action, resource, hash..."
            className="w-full bg-surface-elevated pl-9 pr-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 placeholder-slate-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
            <Filter className="h-3 w-3" /> Action:
          </span>
          <select
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value)}
            className="bg-surface-elevated text-xs text-slate-200 border border-slate-700 rounded px-2.5 py-1.5 focus:outline-none focus:border-red-500 font-mono"
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

      {/* Audit Log Table */}
      <div className="bg-surface-base border border-slate-800 rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-surface-elevated border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th className="py-2.5 px-4 font-semibold">Timestamp (UTC)</th>
                <th className="py-2.5 px-4 font-semibold">Action Verb</th>
                <th className="py-2.5 px-4 font-semibold">Resource Affected</th>
                <th className="py-2.5 px-4 font-semibold">Client IP</th>
                <th className="py-2.5 px-4 font-semibold">Merkle Hash Chain Link</th>
                <th className="py-2.5 px-4 font-semibold text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 font-mono text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-cyan-400" />
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
                    className="hover:bg-surface-elevated/80 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3 text-slate-500" />
                        {new Date(log.created_at).toISOString().replace("T", " ").slice(0, 19)}
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">{getActionBadge(log.action)}</td>

                    <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                      <span className="font-semibold text-slate-200">{log.resource_type}</span>
                      {log.resource_id && (
                        <span className="text-[10px] text-slate-500 ml-1.5">
                          ({log.resource_id.slice(0, 8)}...)
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                      {log.ip_address || "N/A"}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1 text-[10px] text-slate-500">
                        <span className="text-slate-400 font-mono truncate max-w-[90px]" title={log.prev_hash}>
                          {log.prev_hash?.slice(0, 10)}...
                        </span>
                        <ArrowRight className="h-3 w-3 text-cyan-500 shrink-0" />
                        <span className="text-cyan-400 font-mono truncate max-w-[90px]" title={log.hash}>
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
                        className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 group-hover:underline"
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
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-surface-base border border-slate-800 rounded-lg max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Database className="h-5 w-5 text-cyan-400" />
                <h3 className="text-base font-bold text-slate-100">Audit Ledger Block Inspection</h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-slate-500 hover:text-slate-300 font-mono"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 bg-surface-elevated rounded border border-slate-800 text-slate-300">
                <div>
                  <span className="text-slate-500">Action:</span> {selectedLog.action}
                </div>
                <div>
                  <span className="text-slate-500">Resource:</span> {selectedLog.resource_type}
                </div>
                <div>
                  <span className="text-slate-500">Timestamp:</span> {selectedLog.created_at}
                </div>
                <div>
                  <span className="text-slate-500">IP Address:</span> {selectedLog.ip_address || "N/A"}
                </div>
              </div>

              {/* Hash Chain Details */}
              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-2 text-[11px]">
                <div>
                  <span className="text-slate-500">Previous Hash (H_prev):</span>
                  <div className="text-slate-400 break-all">{selectedLog.prev_hash}</div>
                </div>
                <div>
                  <span className="text-slate-500">Block SHA-256 Digest (H_curr):</span>
                  <div className="text-cyan-400 break-all">{selectedLog.hash}</div>
                </div>
              </div>

              {/* Serialized Details Payload */}
              <div>
                <span className="text-slate-400 block mb-1">State Modification Delta (JSON Payload):</span>
                <pre className="p-3 rounded bg-black/80 border border-slate-800 text-[11px] text-emerald-400 overflow-x-auto max-h-56">
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono"
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
