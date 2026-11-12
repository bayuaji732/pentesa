"use client";

import React, { useEffect, useState } from "react";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/lib/ToastContext";
import { api } from "@/lib/api";
import { EngagementStepper } from "@/components/EngagementStepper";
import { StepFooterNav } from "@/components/StepFooterNav";
import {
  AlertTriangle,
  ShieldCheck,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Copy,
  ChevronRight,
  Terminal,
  Code2,
  Clock,
  Fingerprint,
} from "lucide-react";

export default function FindingsPage() {
  const { currentProject } = useProject();
  const { toast } = useToast();
  const [findings, setFindings] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  // Selected finding for evidence inspection drawer
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [evidenceList, setEvidenceList] = useState<any[]>([]);
  const [loadingEvidence, setLoadingEvidence] = useState(false);
  const [activeEvidenceTab, setActiveEvidenceTab] = useState<"request" | "response" | "curl">("request");

  // Retest state
  const [retesting, setRetesting] = useState(false);
  const [retestResult, setRetestResult] = useState<any | null>(null);

  // Deduplication state
  const [dedupModalOpen, setDedupModalOpen] = useState(false);
  const [dedupData, setDedupData] = useState<any | null>(null);
  const [dedupLoading, setDedupLoading] = useState(false);

  // New Finding Modal
  const emptyFindingForm = {
    title: "",
    description: "",
    severity: "High",
    cwe_id: "",
    wstg_id: "",
    affected_parameter: "",
    cvss_score: "",
    remediation_guidance: "",
    raw_request: "",
    raw_response: "",
  };
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [newFinding, setNewFinding] = useState(emptyFindingForm);
  const [submittingFinding, setSubmittingFinding] = useState(false);

  const fetchFindings = async () => {
    if (!currentProject) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data: any = await api.listFindings(currentProject.id);
      const list = Array.isArray(data) ? data : Array.isArray(data?.items) ? data.items : [];
      setFindings(list);
      if (selectedFinding) {
        const updated = list.find((f: any) => f.id === selectedFinding.id);
        setSelectedFinding(updated || null);
      }
    } catch (err: any) {
      console.error(err);
      setError(err?.message || "Failed to load findings from repository.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
    setRetestResult(null);
  }, [currentProject?.id]);

  const handleSelectFinding = async (finding: any) => {
    setSelectedFinding(finding);
    setRetestResult(null);
    if (!currentProject) return;

    setLoadingEvidence(true);
    try {
      const evidence = await api.getFindingEvidence(currentProject.id, finding.id);
      setEvidenceList(evidence || []);
    } catch (err) {
      console.error("Failed to load evidence", err);
      setEvidenceList([]);
    } finally {
      setLoadingEvidence(false);
    }
  };

  const handleRetest = async () => {
    if (!currentProject || !selectedFinding) return;
    setRetesting(true);
    setRetestResult(null);
    try {
      const res = await api.retestFinding(currentProject.id, selectedFinding.id);
      setRetestResult(res);
      await fetchFindings();
      toast.success(res.is_remediated ? "Fix verified: Vulnerability remediated." : "Exploit reproduction succeeded: target still vulnerable.");
    } catch (err: any) {
      toast.error("Retest failed: " + (err?.message || "Unknown error"));
    } finally {
      setRetesting(false);
    }
  };

  const handleStatusChange = async (newStatus: string) => {
    if (!currentProject || !selectedFinding) return;
    try {
      await api.updateFindingStatus(
        currentProject.id,
        selectedFinding.id,
        newStatus,
        `Triage status transition to ${newStatus} via SOC Console`
      );
      await fetchFindings();
      toast.success(`Finding status transitioned to "${newStatus}".`);
    } catch (err: any) {
      toast.error("Status update failed: " + (err?.message || "Error"));
    }
  };

  const handleDeduplicate = async () => {
    if (!currentProject) return;
    setDedupLoading(true);
    setDedupModalOpen(true);
    try {
      const data = await api.deduplicateFindings(currentProject.id);
      setDedupData(data);
    } catch (err: any) {
      toast.error("Deduplication error: " + (err?.message || "Error"));
    } finally {
      setDedupLoading(false);
    }
  };

  const handleCreateFinding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject) return;
    setSubmittingFinding(true);
    try {
      const parsedCvss =
        newFinding.cvss_score.trim() !== "" && !Number.isNaN(Number(newFinding.cvss_score))
          ? Number(newFinding.cvss_score)
          : undefined;
      await api.createFinding(currentProject.id, {
        title: newFinding.title.trim(),
        description: newFinding.description.trim(),
        severity: newFinding.severity,
        ...(newFinding.cwe_id.trim() ? { cwe_id: newFinding.cwe_id.trim() } : {}),
        ...(newFinding.wstg_id.trim() ? { wstg_id: newFinding.wstg_id.trim() } : {}),
        ...(newFinding.affected_parameter.trim()
          ? { affected_parameter: newFinding.affected_parameter.trim() }
          : {}),
        ...(parsedCvss !== undefined ? { cvss_score: parsedCvss } : {}),
        ...(newFinding.remediation_guidance.trim()
          ? { remediation_guidance: newFinding.remediation_guidance.trim() }
          : {}),
        ...(newFinding.raw_request.trim() ? { raw_request: newFinding.raw_request } : {}),
        ...(newFinding.raw_response.trim() ? { raw_response: newFinding.raw_response } : {}),
        detection_source: "manual",
      });
      setCreateModalOpen(false);
      setNewFinding(emptyFindingForm);
      await fetchFindings();
      toast.success("Security finding registered successfully.");
    } catch (err: any) {
      toast.error("Creation failed: " + (err?.message || "Error"));
    } finally {
      setSubmittingFinding(false);
    }
  };

  // Severity Counts
  const counts = {
    ALL: findings.length,
    Critical: findings.filter((f) => f.severity?.toUpperCase() === "CRITICAL").length,
    High: findings.filter((f) => f.severity?.toUpperCase() === "HIGH").length,
    Medium: findings.filter((f) => f.severity?.toUpperCase() === "MEDIUM").length,
    Low: findings.filter((f) => f.severity?.toUpperCase() === "LOW").length,
    Informational: findings.filter(
      (f) => f.severity?.toUpperCase() === "INFORMATIONAL" || f.severity?.toUpperCase() === "INFO"
    ).length,
  };

  // Filtered List
  const filteredFindings = findings.filter((f) => {
    const sev = f.severity?.toUpperCase() || "";
    if (selectedSeverity !== "ALL" && sev !== selectedSeverity.toUpperCase()) {
      return false;
    }
    if (statusFilter !== "ALL" && f.status !== statusFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchTitle = f.title?.toLowerCase().includes(q);
      const matchDesc = f.description?.toLowerCase().includes(q);
      const matchCwe = f.cwe_id?.toLowerCase().includes(q);
      const matchParam = f.affected_parameter?.toLowerCase().includes(q);
      if (!matchTitle && !matchDesc && !matchCwe && !matchParam) return false;
    }
    return true;
  });

  const getSeverityBadge = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === "CRITICAL") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-50 text-rose-800 border border-rose-200">
          <span className="h-1.5 w-1.5 rounded-full bg-rose-600 animate-pulse" />
          CRITICAL
        </span>
      );
    }
    if (s === "HIGH") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-orange-50 text-orange-800 border border-orange-200">
          <span className="h-1.5 w-1.5 rounded-full bg-orange-600" />
          HIGH
        </span>
      );
    }
    if (s === "MEDIUM") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">
          <span className="h-1.5 w-1.5 rounded-full bg-amber-600" />
          MEDIUM
        </span>
      );
    }
    if (s === "LOW") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-blue-50 text-blue-800 border border-blue-200">
          <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
          LOW
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
        <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
        INFO
      </span>
    );
  };

  const getStatusBadge = (status: string) => {
    const s = status?.toLowerCase();
    if (s === "remediated" || s === "closed") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
          <CheckCircle2 className="h-3 w-3 text-emerald-600" />
          Remediated
        </span>
      );
    }
    if (s === "confirmed") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-50 text-rose-800 border border-rose-200">
          <AlertTriangle className="h-3 w-3 text-rose-600" />
          Confirmed
        </span>
      );
    }
    if (s === "false positive") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-600 border border-slate-200">
          <XCircle className="h-3 w-3" />
          False Positive
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-100 text-slate-700 border border-slate-200">
        {status || "Detected"}
      </span>
    );
  };

  if (!currentProject) {
    return (
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center text-xs font-mono text-slate-500 bg-white border border-slate-200 rounded-xl shadow-xs">
          Please select an active engagement to view findings and retest engine.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <EngagementStepper />
      {/* Header and Action Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900">Findings & Retest Engine</h1>
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {findings.length} Total
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Empirical vulnerability triage, cryptographic evidence digests, and one-click patch verification.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={handleDeduplicate}
            className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-white hover:bg-slate-50 text-xs font-mono text-slate-700 border border-slate-200 shadow-xs transition-colors cursor-pointer"
          >
            <Fingerprint className="h-3.5 w-3.5 text-blue-700" />
            Deduplication Clusters
          </button>
          <button
            onClick={() => setCreateModalOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-blue-900 hover:bg-blue-800 text-xs font-semibold text-white shadow-xs transition-colors cursor-pointer"
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            + Register Finding
          </button>
          <button
            onClick={fetchFindings}
            disabled={loading}
            className="p-2 rounded-md bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 border border-slate-200 shadow-xs transition-colors"
            title="Refresh findings"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-700" : ""}`} />
          </button>
        </div>
      </div>

      {/* Severity Filter Pills */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5">
        {[
          { key: "ALL", label: "All Findings", count: counts.ALL, active: "border-blue-900 bg-blue-50 text-blue-900 font-bold ring-1 ring-blue-900/30" },
          { key: "Critical", label: "Critical", count: counts.Critical, active: "border-rose-600 bg-rose-50 text-rose-800 font-bold ring-1 ring-rose-600/30" },
          { key: "High", label: "High", count: counts.High, active: "border-orange-600 bg-orange-50 text-orange-800 font-bold ring-1 ring-orange-600/30" },
          { key: "Medium", label: "Medium", count: counts.Medium, active: "border-amber-600 bg-amber-50 text-amber-800 font-bold ring-1 ring-amber-600/30" },
          { key: "Low", label: "Low", count: counts.Low, active: "border-blue-600 bg-blue-50 text-blue-800 font-bold ring-1 ring-blue-600/30" },
          { key: "Informational", label: "Informational", count: counts.Informational, active: "border-slate-400 bg-slate-100 text-slate-900 font-bold ring-1 ring-slate-400/30" },
        ].map((tab) => {
          const isSelected = selectedSeverity === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => setSelectedSeverity(tab.key)}
              className={`flex items-center justify-between p-3 rounded-xl border transition-all text-left shadow-xs cursor-pointer ${
                isSelected
                  ? tab.active
                  : "border-slate-200 bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50"
              }`}
            >
              <span className="text-xs font-semibold">{tab.label}</span>
              <span
                className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                  isSelected ? "bg-white/80 shadow-xs" : "bg-slate-100 text-slate-700 border border-slate-200"
                }`}
              >
                {tab.count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Search and Secondary Filter Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-white p-3 rounded-xl border border-slate-200 shadow-xs">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-3 h-3.5 w-3.5 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by title, CWE, parameter..."
            className="w-full bg-white pl-9 pr-3 py-1.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-mono transition-all"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-[11px] font-mono text-slate-500 font-semibold flex items-center gap-1">
            <Filter className="h-3 w-3" /> Status:
          </span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-white text-xs text-slate-900 border border-slate-300 rounded-md px-3 py-1.5 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
          >
            <option value="ALL">All Statuses</option>
            <option value="Detected">Detected</option>
            <option value="Triaged">Triaged</option>
            <option value="Confirmed">Confirmed</option>
            <option value="Remediated">Remediated</option>
            <option value="False Positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Main View: Split Layout (Findings List & Selected Evidence Drawer) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Findings List */}
        <div className={selectedFinding ? "lg:col-span-6 space-y-3" : "lg:col-span-12 space-y-3"}>
          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="h-24 bg-white border border-slate-200 rounded-xl animate-pulse shadow-xs" />
              ))}
            </div>
          ) : filteredFindings.length === 0 ? (
            <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-xs">
              <ShieldCheck className="h-10 w-10 text-emerald-600 mx-auto mb-3" />
              <p className="text-sm font-bold text-slate-900">Zero active findings matching query</p>
              <p className="text-xs text-slate-500 mt-1">
                The target perimeter has no reported issues under current filter parameters.
              </p>
            </div>
          ) : (
            filteredFindings.map((finding) => {
              const isSelected = selectedFinding?.id === finding.id;
              return (
                <div
                  key={finding.id}
                  onClick={() => handleSelectFinding(finding)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer shadow-xs ${
                    isSelected
                      ? "bg-blue-50/40 border-blue-600 ring-2 ring-blue-600/20"
                      : "bg-white border-slate-200 hover:border-slate-300 hover:shadow-sm"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-2">
                        {getSeverityBadge(finding.severity)}
                        {finding.cvss_score && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-800 border border-slate-200 font-bold">
                            CVSS {finding.cvss_score}
                          </span>
                        )}
                        {finding.cwe_id && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-900 border border-blue-200 font-semibold">
                            {finding.cwe_id}
                          </span>
                        )}
                        {finding.wstg_id && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                            {finding.wstg_id}
                          </span>
                        )}
                        {getStatusBadge(finding.status)}
                      </div>

                      <h3 className="text-sm font-bold text-slate-900 hover:text-blue-900 transition-colors">
                        {finding.title}
                      </h3>

                      <p className="text-xs text-slate-600 line-clamp-2 leading-normal">{finding.description}</p>
                    </div>

                    <ChevronRight
                      className={`h-5 w-5 text-slate-400 shrink-0 transition-transform ${
                        isSelected ? "rotate-90 text-blue-900" : ""
                      }`}
                    />
                  </div>

                  <div className="flex items-center justify-between mt-3 pt-3 border-t border-slate-100 text-[11px] font-mono text-slate-500">
                    <span className="truncate max-w-[280px]">
                      {finding.affected_parameter ? (
                        <>
                          Param: <span className="text-slate-800 font-semibold">{finding.affected_parameter}</span>
                        </>
                      ) : (
                        `Src: ${finding.detection_source || "scanner"}`
                      )}
                    </span>
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {new Date(finding.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Selected Finding Forensic Evidence & Retest Drawer */}
        {selectedFinding && (
          <div className="lg:col-span-6 space-y-4 bg-white p-5 rounded-xl border border-slate-200 sticky top-20 max-h-[calc(100vh-6rem)] overflow-y-auto shadow-sm">
            {/* Header */}
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-100">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  {getSeverityBadge(selectedFinding.severity)}
                  {getStatusBadge(selectedFinding.status)}
                </div>
                <h2 className="text-base font-bold text-slate-900">{selectedFinding.title}</h2>
                <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
                  <span>ID: {selectedFinding.id.slice(0, 8)}...</span>
                  {selectedFinding.cvss_vector && (
                    <span className="text-[10px] text-slate-600 bg-slate-100 border border-slate-200 px-1.5 py-0.5 rounded truncate max-w-[200px]" title={selectedFinding.cvss_vector}>
                      {selectedFinding.cvss_vector}
                    </span>
                  )}
                </div>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-slate-700 text-xs font-mono p-1"
              >
                ✕ Close
              </button>
            </div>

            {/* Status Transition Control */}
            <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-700">Lifecycle Status:</span>
              <div className="flex items-center gap-2">
                <select
                  value={selectedFinding.status}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  className="bg-white text-xs text-slate-900 border border-slate-300 rounded px-2.5 py-1 font-mono focus:outline-none focus:border-blue-600"
                >
                  <option value="Detected">Detected</option>
                  <option value="Triaged">Triaged</option>
                  <option value="Confirmed">Confirmed</option>
                  <option value="Remediated">Remediated</option>
                  <option value="False Positive">False Positive</option>
                  <option value="Accepted Risk">Accepted Risk</option>
                </select>
              </div>
            </div>

            {/* Empirical Patch Retest Suite */}
            <div className="p-4 bg-slate-50 rounded-lg border border-slate-200 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-bold text-blue-900">
                  <Terminal className="h-4 w-4" />
                  Empirical Patch Retest Engine
                </div>
                <button
                  onClick={handleRetest}
                  disabled={retesting}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-900 hover:bg-blue-800 disabled:opacity-50 text-xs font-semibold text-white shadow-xs transition-colors cursor-pointer"
                >
                  <RefreshCw className={`h-3 w-3 ${retesting ? "animate-spin" : ""}`} />
                  {retesting ? "Executing Retest..." : "Verify Fix"}
                </button>
              </div>
              <p className="text-[11px] text-slate-600 leading-normal">
                Re-executes the exact exploit reproduction recipe against the target endpoint to verify if the remediation patch blocked the attack.
              </p>

              {retestResult && (
                <div
                  className={`p-3 rounded-lg border text-xs font-mono space-y-1.5 ${
                    retestResult.is_remediated
                      ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                      : "bg-rose-50 border-rose-200 text-rose-800"
                  }`}
                >
                  <div className="flex items-center justify-between font-bold">
                    <span>
                      {retestResult.is_remediated ? "✔ Remediated (Vulnerability Closed)" : "✘ Vulnerable (Exploit Succeeded)"}
                    </span>
                    <span>
                      {retestResult.http_status_code != null
                        ? `HTTP ${retestResult.http_status_code}`
                        : "Unreachable"}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-700">{retestResult.verification_notes}</p>
                </div>
              )}
            </div>

            {/* Description & Impact */}
            <div className="space-y-1.5">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 font-bold">
                Vulnerability Description
              </h4>
              <p className="text-xs text-slate-800 leading-relaxed bg-slate-50 p-3.5 rounded-lg border border-slate-200 font-sans">
                {selectedFinding.description}
              </p>
            </div>

            {/* Remediation Guidance */}
            {selectedFinding.remediation_guidance && (
              <div className="space-y-1.5">
                <h4 className="text-xs font-mono uppercase tracking-wider text-emerald-800 font-bold flex items-center gap-1.5">
                  <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" /> Remediation Guidance
                </h4>
                <div className="text-xs text-slate-800 font-mono bg-emerald-50 border border-emerald-200 p-3.5 rounded-lg">
                  {selectedFinding.remediation_guidance}
                </div>
              </div>
            )}

            {/* Forensic Evidence Suite */}
            <div className="space-y-2 pt-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-500 font-bold flex items-center gap-1.5">
                  <Code2 className="h-3.5 w-3.5 text-blue-900" /> Forensic Evidence Artifacts
                </h4>
                <span className="text-[10px] font-mono text-slate-500 font-semibold">
                  {evidenceList.length} evidence captures
                </span>
              </div>

              {loadingEvidence ? (
                <div className="h-32 bg-slate-100 rounded-lg animate-pulse" />
              ) : evidenceList.length === 0 ? (
                <div className="p-4 text-center bg-slate-50 rounded-lg border border-slate-200 text-xs text-slate-500">
                  No forensic evidence attached to this record.
                </div>
              ) : (
                <div className="space-y-3">
                  {evidenceList.map((ev, idx) => (
                    <div key={ev.id || idx} className="border border-slate-800 rounded-lg bg-[#0b0f19] overflow-hidden shadow-xs">
                      {/* Evidence Tab Buttons */}
                      <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-[11px] font-mono">
                        <div className="flex gap-2">
                          <button
                            onClick={() => setActiveEvidenceTab("request")}
                            className={`px-2 py-0.5 rounded ${
                              activeEvidenceTab === "request" ? "bg-slate-800 text-sky-400 font-bold" : "text-slate-400 hover:text-slate-200"
                            }`}
                          >
                            HTTP Request
                          </button>
                          <button
                            onClick={() => setActiveEvidenceTab("response")}
                            className={`px-2 py-0.5 rounded ${
                              activeEvidenceTab === "response" ? "bg-slate-800 text-emerald-400 font-bold" : "text-slate-400 hover:text-slate-200"
                            }`}
                          >
                            HTTP Response
                          </button>
                          <button
                            onClick={() => setActiveEvidenceTab("curl")}
                            className={`px-2 py-0.5 rounded ${
                              activeEvidenceTab === "curl" ? "bg-slate-800 text-amber-400 font-bold" : "text-slate-400 hover:text-slate-200"
                            }`}
                          >
                            cURL Proof
                          </button>
                        </div>
                        <button
                          onClick={() => {
                            const text =
                              activeEvidenceTab === "request"
                                ? ev.raw_request
                                : activeEvidenceTab === "response"
                                ? ev.raw_response
                                : ev.reproduction_curl;
                            navigator.clipboard.writeText(text || "");
                            toast.copy("Forensic evidence copied to clipboard.");
                          }}
                          className="flex items-center gap-1 text-slate-400 hover:text-slate-200 cursor-pointer"
                          title="Copy content"
                        >
                          <Copy className="h-3 w-3" /> Copy
                        </button>
                      </div>

                      {/* Evidence Content (Inset Dark Terminal) */}
                      <div className="p-3 max-h-56 overflow-auto font-mono text-[11px] text-slate-200 leading-relaxed bg-[#0b0f19]">
                        {activeEvidenceTab === "request" && (
                          <pre className="whitespace-pre-wrap">{ev.raw_request || "No raw request captured."}</pre>
                        )}
                        {activeEvidenceTab === "response" && (
                          <pre className="whitespace-pre-wrap">{ev.raw_response || "No raw response captured."}</pre>
                        )}
                        {activeEvidenceTab === "curl" && (
                          <pre className="whitespace-pre-wrap text-amber-300">
                            {ev.reproduction_curl || "No reproduction curl generated."}
                          </pre>
                        )}
                      </div>

                      {/* Cryptographic SHA-256 Digest Badges */}
                      <div className="px-3 py-2 bg-slate-900/90 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 space-y-1">
                        <div className="flex items-center justify-between truncate">
                          <span className="flex items-center gap-1 text-slate-400">
                            <Fingerprint className="h-3 w-3 text-sky-400" /> Req SHA-256:
                          </span>
                          <span className="text-slate-400">{ev.request_hash_sha256}</span>
                        </div>
                        <div className="flex items-center justify-between truncate">
                          <span className="flex items-center gap-1 text-slate-400">
                            <Fingerprint className="h-3 w-3 text-emerald-400" /> Resp SHA-256:
                          </span>
                          <span className="text-slate-400">{ev.response_hash_sha256}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Deduplication Clusters Modal */}
      {dedupModalOpen && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Fingerprint className="h-5 w-5 text-blue-900" />
                <h3 className="text-base font-bold text-slate-900">Cryptographic Finding Deduplication</h3>
              </div>
              <button
                onClick={() => setDedupModalOpen(false)}
                className="text-slate-400 hover:text-slate-700 font-mono text-base p-1"
              >
                ✕
              </button>
            </div>

            {dedupLoading ? (
              <div className="py-12 text-center space-y-3">
                <RefreshCw className="h-8 w-8 text-blue-900 animate-spin mx-auto" />
                <p className="text-xs text-slate-500 font-mono">
                  Hashing finding signatures: SHA256(project_id || path || method || param || cwe)...
                </p>
              </div>
            ) : dedupData ? (
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                    <div className="text-lg font-bold font-mono text-slate-900">{dedupData.total_findings}</div>
                    <div className="text-[11px] text-slate-500 font-medium">Total Findings</div>
                  </div>
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                    <div className="text-lg font-bold font-mono text-blue-900">{dedupData.unique_clusters}</div>
                    <div className="text-[11px] text-slate-500 font-medium">Unique Clusters</div>
                  </div>
                  <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-center">
                    <div className="text-lg font-bold font-mono text-amber-800">{dedupData.duplicates_detected}</div>
                    <div className="text-[11px] text-slate-500 font-medium">Duplicates Detected</div>
                  </div>
                </div>

                <div className="space-y-2 max-h-72 overflow-y-auto">
                  {dedupData.clusters?.length === 0 ? (
                    <p className="text-xs text-slate-500 text-center py-4">No duplicate clusters identified.</p>
                  ) : (
                    dedupData.clusters?.map((cluster: any, idx: number) => (
                      <div key={idx} className="p-3 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-blue-900 font-bold">
                            {cluster.primary_title || cluster.title || `Cluster #${idx + 1}`}
                          </span>
                          <span className="text-slate-600 font-semibold">
                            {cluster.duplicate_count != null
                              ? `${cluster.duplicate_count + 1} findings in cluster`
                              : `${cluster.count || 0} findings in cluster`}
                          </span>
                        </div>
                        <div className="text-[10px] font-mono text-slate-400 truncate">
                          Sig: {cluster.signature_hash || cluster.signature}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            ) : null}

            <div className="pt-3 border-t border-slate-100 flex justify-end">
              <button
                onClick={() => setDedupModalOpen(false)}
                className="px-4 py-2 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-xs text-slate-700 font-semibold"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Manual Finding Creation Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreateFinding}
            className="bg-white border border-slate-200 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-xl"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-blue-900" />
                <h3 className="text-base font-bold text-slate-900">Register Security Finding</h3>
              </div>
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="text-slate-400 hover:text-slate-700 font-mono text-base p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3.5 max-h-[70vh] overflow-y-auto pr-1">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Finding Title *</label>
                <input
                  type="text"
                  required
                  value={newFinding.title}
                  onChange={(e) => setNewFinding({ ...newFinding, title: e.target.value })}
                  placeholder="e.g. SQL Injection in product search parameter"
                  className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Severity *</label>
                  <select
                    value={newFinding.severity}
                    onChange={(e) => setNewFinding({ ...newFinding, severity: e.target.value })}
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                  >
                    <option value="Critical">Critical</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">CVSS v3.1 Score</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={newFinding.cvss_score}
                    onChange={(e) => setNewFinding({ ...newFinding, cvss_score: e.target.value })}
                    placeholder="e.g. 8.5"
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">CWE ID</label>
                  <input
                    type="text"
                    value={newFinding.cwe_id}
                    onChange={(e) => setNewFinding({ ...newFinding, cwe_id: e.target.value })}
                    placeholder="CWE-89"
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">WSTG ID</label>
                  <input
                    type="text"
                    value={newFinding.wstg_id}
                    onChange={(e) => setNewFinding({ ...newFinding, wstg_id: e.target.value })}
                    placeholder="WSTG-INPV-05"
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Affected Parameter</label>
                  <input
                    type="text"
                    value={newFinding.affected_parameter}
                    onChange={(e) => setNewFinding({ ...newFinding, affected_parameter: e.target.value })}
                    placeholder="search"
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Technical Description *</label>
                <textarea
                  required
                  rows={3}
                  value={newFinding.description}
                  onChange={(e) => setNewFinding({ ...newFinding, description: e.target.value })}
                  placeholder="Detailed root cause analysis and impact..."
                  className="w-full bg-white p-2.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-sans"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Remediation Guidance</label>
                <textarea
                  rows={2}
                  value={newFinding.remediation_guidance}
                  onChange={(e) => setNewFinding({ ...newFinding, remediation_guidance: e.target.value })}
                  placeholder="Fix recommendation for engineering team..."
                  className="w-full bg-white p-2.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-sans"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Raw HTTP Request (Optional)</label>
                <textarea
                  rows={2}
                  value={newFinding.raw_request}
                  onChange={(e) => setNewFinding({ ...newFinding, raw_request: e.target.value })}
                  placeholder="GET /search?q=test HTTP/1.1&#10;Host: app.organization.com"
                  className="w-full bg-white p-2.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Raw HTTP Response (Optional)</label>
                <textarea
                  rows={2}
                  value={newFinding.raw_response}
                  onChange={(e) => setNewFinding({ ...newFinding, raw_response: e.target.value })}
                  placeholder="HTTP/1.1 200 OK&#10;Content-Type: text/html"
                  className="w-full bg-white p-2.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
                />
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-4 py-2 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-xs text-slate-700 font-semibold"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submittingFinding}
                className="px-4 py-2 rounded-md bg-blue-900 hover:bg-blue-800 disabled:opacity-50 text-xs font-semibold text-white shadow-xs"
              >
                {submittingFinding ? "Saving..." : "Save Finding"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* 6-Phase Linear Bottom Navigation */}
      <StepFooterNav
        currentStep={5}
        prevStepPath="/agents"
        prevStepLabel="Multi-Agent DAG"
        nextStepPath="/reports"
        nextStepLabel="Finalize Findings & Generate PTES Report"
        canAdvance={true}
      />
    </div>
  );
}
