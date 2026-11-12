"use client";

import React, { useEffect, useState } from "react";
import { useProject } from "@/lib/ProjectContext";
import { API_BASE_URL, api, getAuthToken } from "@/lib/api";
import { EngagementStepper } from "@/components/EngagementStepper";
import {
  FileText,
  FileCheck2,
  Download,
  ShieldCheck,
  RefreshCw,
  Copy,
  Lock,
  CheckCircle2,
  AlertCircle,
  Clock,
  Sparkles,
} from "lucide-react";

export default function ReportsPage() {
  const { currentProject } = useProject();
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  // Form state
  const [reportFormat, setReportFormat] = useState<"PDF" | "HTML">("PDF");
  const [reportTitle, setReportTitle] = useState("");
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

  if (!currentProject) {
    return (
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center text-xs font-mono text-slate-500 bg-white border border-slate-200 rounded-xl shadow-xs">
          Please select an active engagement project to view and compile PTES reports.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <EngagementStepper />
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900">PTES Reporting & Cryptographic Seals</h1>
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {reports.length} Published
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Compliant with Penetration Testing Execution Standard (PTES) & OWASP WSTG. Signed with immutable SHA-256 seals.
          </p>
        </div>

        <button
          onClick={fetchReports}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-2 rounded-md bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 border border-slate-200 shadow-xs transition-colors self-start md:self-auto cursor-pointer"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-blue-700" : ""}`} />
          Refresh Deliverables
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left: Report Generator & Seal Verification */}
        <div className="lg:col-span-5 space-y-6">
          {/* Generator Card */}
          <div className="p-5 bg-white rounded-xl border border-slate-200 space-y-4 shadow-xs">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-900 pb-2 border-b border-slate-100">
              <Sparkles className="h-4 w-4 text-blue-900" />
              Compile Formal PTES Report
            </div>

            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Report Format</label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => setReportFormat("PDF")}
                    className={`py-2 px-3 rounded-md border text-xs font-mono font-semibold transition-all cursor-pointer ${
                      reportFormat === "PDF"
                        ? "bg-blue-50 border-blue-600 text-blue-900 ring-1 ring-blue-600/30"
                        : "bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                    }`}
                  >
                    PDF (Print-Ready)
                  </button>
                  <button
                    type="button"
                    onClick={() => setReportFormat("HTML")}
                    className={`py-2 px-3 rounded-md border text-xs font-mono font-semibold transition-all cursor-pointer ${
                      reportFormat === "HTML"
                        ? "bg-blue-50 border-blue-600 text-blue-900 ring-1 ring-blue-600/30"
                        : "bg-white border-slate-300 text-slate-700 hover:bg-slate-50"
                    }`}
                  >
                    HTML (Interactive)
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Deliverable Title</label>
                <input
                  type="text"
                  required
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  placeholder="e.g. Q4 Web Application Security Assessment Report"
                  className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-sans"
                />
              </div>

              <div className="space-y-2 pt-1">
                <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={includeEvidence}
                    onChange={(e) => setIncludeEvidence(e.target.checked)}
                    className="rounded border-slate-300 text-blue-900 focus:ring-blue-600"
                  />
                  <span>Attach Raw HTTP Forensic Streams & cURL</span>
                </label>
                <label className="flex items-center gap-2 text-xs text-slate-400 cursor-not-allowed">
                  <input type="checkbox" checked disabled className="rounded border-slate-200" />
                  <span>Enforce Sequential Merkle Audit Seal (Mandatory)</span>
                </label>
              </div>

              <button
                type="submit"
                disabled={generating}
                className="w-full flex items-center justify-center gap-2 py-2 rounded-md bg-blue-900 hover:bg-blue-800 disabled:opacity-50 text-xs font-semibold text-white transition-colors shadow-xs cursor-pointer"
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
                className={`p-3 rounded-lg border text-xs font-mono ${
                  statusBanner.type === "success"
                    ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                    : "bg-rose-50 border-rose-200 text-rose-800"
                }`}
              >
                {statusBanner.text}
              </div>
            )}
          </div>

          {/* Cryptographic Seal Verification Tool */}
          <div className="p-5 bg-white rounded-xl border border-slate-200 space-y-4 shadow-xs">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-900 pb-2 border-b border-slate-100">
              <Lock className="h-4 w-4 text-blue-900" />
              Cryptographic Seal Verification
            </div>
            <p className="text-xs text-slate-500 leading-normal">
              Paste the SHA-256 digest of any deliverable to verify against immutable platform ledger seals.
            </p>

            <form onSubmit={handleVerifySeal} className="space-y-3">
              <input
                type="text"
                required
                value={verifyHash}
                onChange={(e) => setVerifyHash(e.target.value)}
                placeholder="Paste SHA-256 hash (64 hex characters)..."
                className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono"
              />

              <button
                type="submit"
                disabled={verifying}
                className="w-full flex items-center justify-center gap-1.5 py-2 rounded-md bg-white hover:bg-slate-50 text-xs font-semibold text-blue-900 border border-blue-300 shadow-xs transition-colors cursor-pointer"
              >
                {verifying ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                Verify Integrity Seal
              </button>
            </form>

            {verifyResult && (
              <div
                className={`p-3.5 rounded-lg border text-xs font-mono space-y-1.5 ${
                  verifyResult.verified
                    ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                    : "bg-rose-50 border-rose-200 text-rose-800"
                }`}
              >
                <div className="flex items-center gap-1.5 font-bold">
                  {verifyResult.verified ? (
                    <>
                      <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                      Cryptographic Seal Verified
                    </>
                  ) : (
                    <>
                      <AlertCircle className="h-4 w-4 text-rose-600" />
                      Verification Failed
                    </>
                  )}
                </div>
                <p className="text-[11px] text-slate-700">{verifyResult.message}</p>
                {verifyResult.title && (
                  <div className="text-[10px] text-slate-600 space-y-0.5 pt-1.5 border-t border-slate-200">
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
          <div className="flex items-center justify-between pb-1">
            <h3 className="text-sm font-bold text-slate-900">Published Security Deliverables</h3>
            <span className="text-xs font-mono text-slate-500 font-medium">Immutable PTES Artifacts</span>
          </div>

          {loading ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-28 bg-white border border-slate-200 rounded-xl animate-pulse shadow-xs" />
              ))}
            </div>
          ) : reports.length === 0 ? (
            <div className="p-12 text-center bg-white border border-slate-200 rounded-xl space-y-3 shadow-xs">
              <FileText className="h-10 w-10 text-slate-400 mx-auto" />
              <p className="text-sm font-bold text-slate-900">Zero formal reports published yet</p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto leading-normal">
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
                  className="p-5 rounded-xl border border-slate-200 bg-white hover:border-slate-300 transition-all space-y-3 shadow-xs"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            isPdf
                              ? "bg-rose-50 text-rose-800 border-rose-200"
                              : "bg-blue-50 text-blue-800 border-blue-200"
                          }`}
                        >
                          <span className={`h-1.5 w-1.5 rounded-full ${isPdf ? "bg-rose-600" : "bg-blue-600"}`} />
                          {report.format || "PDF"}
                        </span>
                        <span className="text-xs font-mono text-slate-500">
                          {report.file_size_bytes
                            ? formatBytes(report.file_size_bytes)
                            : `${report.report_metadata?.total_findings ?? 0} Findings • ${Number(report.report_metadata?.coverage_score ?? 0).toFixed(1)}% WSTG`}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-slate-900">{report.title}</h4>
                    </div>

                    <a
                      href={downloadUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      download
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-900 hover:bg-blue-800 text-xs font-semibold text-white shadow-xs transition-colors shrink-0"
                    >
                      <Download className="h-3.5 w-3.5" />
                      Download
                    </a>
                  </div>

                  {/* Cryptographic SHA-256 Digest Bar */}
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between text-[11px] font-mono text-slate-600">
                    <div className="flex items-center gap-2 truncate">
                      <Lock className="h-3.5 w-3.5 text-blue-900 shrink-0" />
                      <span className="text-slate-500 shrink-0 font-medium">SHA-256 Seal:</span>
                      <span className="text-slate-800 truncate font-semibold">{report.file_hash_sha256}</span>
                    </div>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(report.file_hash_sha256);
                        alert("SHA-256 seal copied to clipboard!");
                      }}
                      className="text-slate-400 hover:text-slate-700 p-1 shrink-0 cursor-pointer"
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
                      className="text-blue-700 hover:text-blue-900 hover:underline text-[11px] font-semibold"
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
