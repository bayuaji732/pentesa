"use client";

import React, { useEffect, useState } from "react";
import { useProject } from "@/lib/ProjectContext";
import { API_BASE_URL, api, getAuthToken } from "@/lib/api";
import {
  FileText,
  FileCheck2,
  Download,
  ShieldCheck,
  RefreshCw,
  Copy,
  ExternalLink,
  Lock,
  CheckCircle2,
  AlertCircle,
  Clock,
  Sparkles,
  Search,
} from "lucide-react";

export default function ReportsPage() {
  const { currentProject } = useProject();
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  // Form state
  const [reportFormat, setReportFormat] = useState<"PDF" | "HTML">("PDF");
  const [reportTitle, setReportTitle] = useState("PTES Penetration Testing Executive & Technical Report");
  const [includeEvidence, setIncludeEvidence] = useState(true);

  // Verification state
  const [verifyHash, setVerifyHash] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<any | null>(null);
  const [statusBanner, setStatusBanner] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const fetchReports = async () => {
    if (!currentProject) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data: any = await api.listReports(currentProject.id);
      setReports(Array.isArray(data) ? data : Array.isArray(data?.items) ? data.items : []);
    } catch (err) {
      console.error("Failed to load reports", err);
      setReports([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [currentProject?.id]);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject) return;
    setGenerating(true);
    setStatusBanner(null);
    try {
      const created = await api.generateReport(currentProject.id, reportFormat, reportTitle, includeEvidence);
      await fetchReports();
      setStatusBanner({
        type: "success",
        text: `${reportFormat} deliverable compiled cleanly (${created?.title || reportTitle}).`,
      });
    } catch (err: any) {
      setStatusBanner({
        type: "error",
        text: "Failed to compile report: " + (err?.message || "Error"),
      });
    } finally {
      setGenerating(false);
    }
  };

  const handleVerifySeal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifyHash.trim()) return;
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await api.verifyReport(verifyHash.trim());
      setVerifyResult(res);
    } catch (err: any) {
      setVerifyResult({
        verified: false,
        message: err?.message || "Cryptographic seal verification failed. Report hash not found.",
      });
    } finally {
      setVerifying(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (!bytes) return "0 B";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-100">PTES Reporting & Cryptographic Seals</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {reports.length} Published
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Compliant with Penetration Testing Execution Standard (PTES) & OWASP WSTG. Signed with immutable SHA-256 seals.
          </p>
        </div>

        <button
          onClick={fetchReports}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 self-start md:self-auto"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          Refresh Deliverables
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Report Generator & Seal Verification */}
        <div className="lg:col-span-5 space-y-6">
          {/* Generator Card */}
          <div className="p-5 bg-surface-base rounded border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-100 pb-2 border-b border-slate-800">
              <Sparkles className="h-4 w-4 text-red-500" />
              Compile Formal PTES Report
            </div>

            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Report Format</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setReportFormat("PDF")}
                    className={`py-2 px-3 rounded border text-xs font-mono font-semibold transition-all ${
                      reportFormat === "PDF"
                        ? "bg-red-950/60 border-red-600 text-red-300 shadow-md shadow-red-950/30"
                        : "bg-surface-elevated border-slate-700 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    PDF (Print-Ready)
                  </button>
                  <button
                    type="button"
                    onClick={() => setReportFormat("HTML")}
                    className={`py-2 px-3 rounded border text-xs font-mono font-semibold transition-all ${
                      reportFormat === "HTML"
                        ? "bg-cyan-950/60 border-cyan-600 text-cyan-300 shadow-md shadow-cyan-950/30"
                        : "bg-surface-elevated border-slate-700 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    HTML (Interactive)
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Deliverable Title</label>
                <input
                  type="text"
                  required
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                />
              </div>

              <div className="space-y-2 pt-1">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeEvidence}
                    onChange={(e) => setIncludeEvidence(e.target.checked)}
                    className="rounded bg-surface-elevated border-slate-700 text-red-600 focus:ring-0"
                  />
                  <span>Attach Raw HTTP Forensic Streams & cURL</span>
                </label>
                <label className="flex items-center gap-2 text-xs text-slate-400 cursor-not-allowed">
                  <input type="checkbox" checked disabled className="rounded bg-slate-900 border-slate-800" />
                  <span>Enforce Sequential Merkle Audit Seal (Mandatory)</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={generating}
                className="w-full flex items-center justify-center gap-2 py-2 rounded bg-red-600 hover:bg-red-500 disabled:opacity-50 text-xs font-semibold text-white transition-colors shadow-lg shadow-red-950/50 font-mono"
              >
                {generating ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Compiling Document...
                  </>
                ) : (
                  <>
                    <FileCheck2 className="h-4 w-4" />
                    Generate & Publish Report
                  </>
                )}
              </button>
            </form>

            {statusBanner && (
              <div
                className={`p-2.5 rounded border text-xs font-mono ${
                  statusBanner.type === "success"
                    ? "bg-emerald-950/60 border-emerald-800 text-emerald-300"
                    : "bg-red-950/60 border-red-800 text-red-300"
                }`}
              >
                {statusBanner.text}
              </div>
            )}
          </div>

          {/* Cryptographic Seal Verification Tool */}
          <div className="p-5 bg-surface-base rounded border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-100 pb-2 border-b border-slate-800">
              <Lock className="h-4 w-4 text-cyan-400" />
              Cryptographic Seal Verification
            </div>
            <p className="text-xs text-slate-400">
              Paste the SHA-256 digest of any deliverable to verify against immutable platform ledger seals.
            </p>

            <form onSubmit={handleVerifySeal} className="space-y-3">
              <input
                type="text"
                required
                value={verifyHash}
                onChange={(e) => setVerifyHash(e.target.value)}
                placeholder="Paste SHA-256 hash (64 hex characters)..."
                className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-cyan-500 font-mono"
              />

              <button
                type="submit"
                disabled={verifying}
                className="w-full flex items-center justify-center gap-1.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-400 border border-cyan-900 transition-colors"
              >
                {verifying ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                Verify Integrity Seal
              </button>
            </form>

            {verifyResult && (
              <div
                className={`p-3 rounded border text-xs font-mono space-y-1.5 ${
                  verifyResult.verified
                    ? "bg-emerald-950/70 border-emerald-800 text-emerald-300"
                    : "bg-red-950/70 border-red-800 text-red-300"
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold">
                  {verifyResult.verified ? (
                    <>
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      Cryptographic Seal Verified
                    </>
                  ) : (
                    <>
                      <AlertCircle className="h-4 w-4 text-red-400" />
                      Verification Failed
                    </>
                  )}
                </div>
                <p className="text-[11px] text-slate-300">{verifyResult.message}</p>
                {verifyResult.title && (
                  <div className="text-[10px] text-slate-400 space-y-0.5 pt-1 border-t border-slate-800">
                    <div>Title: {verifyResult.title}</div>
                    <div>Project: {verifyResult.project_name}</div>
                    <div>Format: {verifyResult.file_format || verifyResult.format || "PDF"}</div>
                    <div>
                      Published:{" "}
                      {verifyResult.generated_at || verifyResult.created_at
                        ? new Date(verifyResult.generated_at || verifyResult.created_at).toLocaleString()
                        : "N/A"}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right: Published Reports History */}
        <div className="lg:col-span-7 space-y-3">
          <div className="flex items-center justify-between pb-2">
            <h3 className="text-sm font-semibold text-slate-200">Published Security Deliverables</h3>
            <span className="text-xs font-mono text-slate-500">Immutable PTES Artifacts</span>
          </div>

          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-28 bg-surface-base border border-slate-800 rounded animate-pulse" />
              ))}
            </div>
          ) : reports.length === 0 ? (
            <div className="p-12 text-center bg-surface-base border border-slate-800 rounded space-y-3">
              <FileText className="h-10 w-10 text-slate-600 mx-auto" />
              <p className="text-sm font-semibold text-slate-300">Zero formal reports published yet</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                Use the generator panel on the left to compile an executive summary, WSTG matrix breakdown, and forensic evidence package.
              </p>
            </div>
          ) : (
            reports.map((report) => {
              const isPdf = report.format?.toUpperCase() === "PDF";
              const token = getAuthToken();
              const downloadUrl = `${API_BASE_URL}/api/v1/reports/${report.id}/download${token ? `?token=${encodeURIComponent(token)}` : ""}`;

              return (
                <div
                  key={report.id}
                  className="p-4 rounded border border-slate-800 bg-surface-base hover:border-slate-700 transition-all space-y-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            isPdf
                              ? "bg-red-950/80 text-red-400 border-red-800"
                              : "bg-cyan-950/80 text-cyan-400 border-cyan-800"
                          }`}
                        >
                          {report.format || "PDF"}
                        </span>
                        <span className="text-xs font-mono text-slate-400">
                          {report.file_size_bytes
                            ? formatBytes(report.file_size_bytes)
                            : `${report.report_metadata?.total_findings ?? 0} Findings • ${Number(report.report_metadata?.coverage_score ?? 0).toFixed(1)}% WSTG`}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-100">{report.title}</h4>
                    </div>

                    <a
                      href={downloadUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      download
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition-colors shrink-0"
                    >
                      <Download className="h-3.5 w-3.5 text-cyan-400" />
                      Download
                    </a>
                  </div>

                  {/* Cryptographic SHA-256 Digest Bar */}
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <div className="flex items-center gap-2 truncate">
                      <Lock className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                      <span className="text-slate-500 shrink-0">SHA-256 Seal:</span>
                      <span className="text-slate-300 truncate">{report.file_hash_sha256}</span>
                    </div>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(report.file_hash_sha256);
                        alert("SHA-256 seal copied to clipboard!");
                      }}
                      className="text-slate-400 hover:text-slate-200 p-1 shrink-0"
                      title="Copy SHA-256"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
                    <span className="flex items-center gap-1">
                      <Clock className="h-3 w-3" /> Published on {new Date(report.created_at).toLocaleString()}
                    </span>
                    <button
                      onClick={() => {
                        setVerifyHash(report.file_hash_sha256);
                        window.scrollTo({ top: 0, behavior: "smooth" });
                      }}
                      className="text-cyan-400 hover:underline text-[10px]"
                    >
                      Verify Authenticity →
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
