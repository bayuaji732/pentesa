"use client";

import React, { useEffect, useState } from "react";
import {
  Globe,
  Radio,
  Server,
  Layers,
  Play,
  CheckCircle2,
  Lock,
  RefreshCw,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/lib/ToastContext";
import { api } from "@/lib/api";
import { EngagementStepper } from "@/components/EngagementStepper";
import { StepFooterNav } from "@/components/StepFooterNav";
import { EngagementStepGuard } from "@/components/EngagementStepGuard";

export default function DiscoveryPage() {
  return (
    <EngagementStepGuard requiredStep={2} stepTitle="Attack Surface Discovery">
      <DiscoveryContent />
    </EngagementStepGuard>
  );
}

function DiscoveryContent() {
  const { currentProject } = useProject();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState<"endpoints" | "domains" | "tech">("endpoints");
  const [endpoints, setEndpoints] = useState<any[]>([]);
  const [domains, setDomains] = useState<any[]>([]);
  const [technologies, setTechnologies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // Crawler State
  const [seedUrl, setSeedUrl] = useState("");
  const [maxDepth, setMaxDepth] = useState(2);
  const [maxPages, setMaxPages] = useState(25);
  const [crawling, setCrawling] = useState(false);
  const [crawlSummary, setCrawlSummary] = useState<any>(null);

  const loadData = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const [eps, doms, techs] = await Promise.allSettled([
        api.getEndpoints(currentProject.id),
        api.getDomains(currentProject.id),
        api.getTechnologies(currentProject.id),
      ]);
      if (eps.status === "fulfilled") {
        const val: any = eps.value;
        const list = Array.isArray(val) ? val : Array.isArray(val?.items) ? val.items : [];
        setEndpoints(list);
      }
      if (doms.status === "fulfilled") {
        const val: any = doms.value;
        const list = Array.isArray(val) ? val : Array.isArray(val?.items) ? val.items : [];
        setDomains(list);
      }
      if (techs.status === "fulfilled") {
        const val: any = techs.value;
        const list = Array.isArray(val) ? val : Array.isArray(val?.items) ? val.items : [];
        setTechnologies(list);
      }
    } catch (err) {
      console.error("Discovery load error", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setCrawlSummary(null);
    loadData();
  }, [currentProject]);

  const handleTriggerCrawl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject) return;
    setCrawling(true);
    try {
      const trimmed = seedUrl.trim();
      const seeds = trimmed ? [trimmed] : undefined;
      const res = await api.triggerCrawl(currentProject.id, maxDepth, maxPages, seeds);
      setCrawlSummary(res);
      await loadData();
      toast.success(`Crawl finished: discovered ${res.endpoints_discovered || 0} endpoints.`);
    } catch (err: any) {
      toast.error(`Crawl failed: ${err.message}`);
    } finally {
      setCrawling(false);
    }
  };

  if (!currentProject) {
    return (
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center text-xs font-mono text-slate-500 bg-white border border-slate-200 rounded-xl shadow-xs">
          Please select an active engagement to view discovered attack surface.
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
            <Globe className="h-5 w-5 text-blue-900" />
            Attack Surface Discovery & Inventory
          </h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Automated scope-enforced web crawling, endpoint inventory, and technology detection.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="p-2 bg-white border border-slate-200 hover:bg-slate-50 rounded-md text-slate-600 hover:text-slate-900 transition-colors shadow-xs"
          title="Refresh discovery inventory"
        >
          <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-700" : ""}`} />
        </button>
      </div>

      {/* Crawl Control & Topology Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Topology Summary Cards */}
        <div className="lg:col-span-1 grid grid-cols-3 gap-2.5">
          <div className="bg-white border border-slate-200 rounded-xl p-3.5 text-center shadow-xs">
            <Radio className="h-4 w-4 text-blue-700 mx-auto mb-1.5" />
            <div className="text-xl font-bold font-mono text-slate-900">{domains.length}</div>
            <div className="text-[11px] text-slate-500 font-medium">Domains</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-3.5 text-center shadow-xs">
            <Layers className="h-4 w-4 text-emerald-600 mx-auto mb-1.5" />
            <div className="text-xl font-bold font-mono text-slate-900">{endpoints.length}</div>
            <div className="text-[11px] text-slate-500 font-medium">Endpoints</div>
          </div>
          <div className="bg-white border border-slate-200 rounded-xl p-3.5 text-center shadow-xs">
            <Server className="h-4 w-4 text-amber-600 mx-auto mb-1.5" />
            <div className="text-xl font-bold font-mono text-slate-900">{technologies.length}</div>
            <div className="text-[11px] text-slate-500 font-medium">Tech Stack</div>
          </div>
        </div>

        {/* Crawler Launch Card */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-3.5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <Play className="h-4 w-4 text-blue-900 fill-current" />
              Automated Scope-Enforced Web Crawler
            </h3>
            {crawlSummary && (
              <span
                className={`text-[11px] font-mono font-medium ${
                  crawlSummary.endpoints_discovered === 0 && crawlSummary.errors?.length > 0
                    ? "text-amber-700"
                    : "text-emerald-700"
                }`}
              >
                Discovered: {crawlSummary.endpoints_discovered} endpoints, {crawlSummary.technologies_detected} technologies
              </span>
            )}
          </div>

          <form onSubmit={handleTriggerCrawl} className="flex flex-wrap items-center gap-3">
            <div className="flex-1 min-w-[220px] flex items-center gap-2 text-xs text-slate-700">
              <label className="shrink-0 font-semibold text-slate-700">Target URL:</label>
              <input
                type="text"
                value={seedUrl}
                onChange={(e) => setSeedUrl(e.target.value)}
                placeholder="https://app.organization.com/ (auto-detect if blank)"
                className="w-full h-9 px-3 bg-white border border-slate-300 rounded-md text-slate-900 font-mono text-xs focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
              />
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-700">
              <label className="font-semibold text-slate-700">Depth:</label>
              <input
                type="number"
                min="1"
                max="5"
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value) || 1)}
                className="w-14 h-9 px-2 bg-white border border-slate-300 rounded-md text-slate-900 font-mono text-center text-xs focus:outline-none focus:border-blue-600"
              />
            </div>

            <div className="flex items-center gap-2 text-xs text-slate-700">
              <label className="font-semibold text-slate-700">Max Pages:</label>
              <input
                type="number"
                min="5"
                max="500"
                value={maxPages}
                onChange={(e) => setMaxPages(parseInt(e.target.value) || 10)}
                className="w-16 h-9 px-2 bg-white border border-slate-300 rounded-md text-slate-900 font-mono text-center text-xs focus:outline-none focus:border-blue-600"
              />
            </div>

            <button
              type="submit"
              disabled={crawling}
              className="px-4 h-9 bg-blue-900 hover:bg-blue-800 text-white rounded-md text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50 shrink-0 cursor-pointer"
            >
              {crawling ? (
                <>
                  <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Crawling Targets...
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5 fill-current" />
                  Start Crawler
                </>
              )}
            </button>
          </form>

          {crawlSummary?.errors && crawlSummary.errors.length > 0 && (
            <div className="p-3 rounded-lg border border-amber-200 bg-amber-50 text-[11px] font-mono text-amber-800 space-y-1">
              <div className="font-bold">
                Crawler Warnings / Connection Errors ({crawlSummary.errors.length}):
              </div>
              {crawlSummary.errors.slice(0, 5).map((errMsg: string, idx: number) => (
                <div key={idx} className="truncate" title={errMsg}>
                  &bull; {errMsg}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Tabs & Inventory Data Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-200 bg-slate-50 px-2 pt-2">
          <button
            onClick={() => setActiveTab("endpoints")}
            className={`px-4 py-2.5 text-xs font-mono font-semibold border-b-2 transition-all ${
              activeTab === "endpoints"
                ? "border-blue-900 text-blue-900 bg-white rounded-t-lg font-bold shadow-xs"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            Discovered Endpoints ({endpoints.length})
          </button>
          <button
            onClick={() => setActiveTab("domains")}
            className={`px-4 py-2.5 text-xs font-mono font-semibold border-b-2 transition-all ${
              activeTab === "domains"
                ? "border-blue-900 text-blue-900 bg-white rounded-t-lg font-bold shadow-xs"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            Subdomains ({domains.length})
          </button>
          <button
            onClick={() => setActiveTab("tech")}
            className={`px-4 py-2.5 text-xs font-mono font-semibold border-b-2 transition-all ${
              activeTab === "tech"
                ? "border-blue-900 text-blue-900 bg-white rounded-t-lg font-bold shadow-xs"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            Detected Technologies ({technologies.length})
          </button>
        </div>

        {/* Tab 1: Endpoints */}
        {activeTab === "endpoints" && (
          <div>
            {endpoints.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-slate-500">
                No endpoints discovered yet. Run the crawler or add endpoints via API.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-50/50 text-slate-600 text-[10px] uppercase border-b border-slate-200 font-bold tracking-wider">
                  <tr>
                    <th className="py-2.5 px-3.5">Method</th>
                    <th className="py-2.5 px-3.5">Host</th>
                    <th className="py-2.5 px-3.5">URL Path</th>
                    <th className="py-2.5 px-3.5">Authentication</th>
                    <th className="py-2.5 px-3.5">Testing Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {endpoints.map((ep) => (
                    <tr key={ep.id} className="hover:bg-slate-50/70 transition-colors">
                      <td className="py-2.5 px-3.5">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold border ${
                            ep.http_method === "GET"
                              ? "bg-blue-50 text-blue-800 border-blue-200"
                              : ep.http_method === "POST"
                              ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                              : ep.http_method === "PUT"
                              ? "bg-amber-50 text-amber-800 border-amber-200"
                              : "bg-rose-50 text-rose-800 border-rose-200"
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              ep.http_method === "GET"
                                ? "bg-blue-600"
                                : ep.http_method === "POST"
                                ? "bg-emerald-600"
                                : ep.http_method === "PUT"
                                ? "bg-amber-600"
                                : "bg-rose-600"
                            }`}
                          />
                          {ep.http_method}
                        </span>
                      </td>
                      <td className="py-2.5 px-3.5 text-slate-700 font-semibold">{ep.fqdn}</td>
                      <td className="py-2.5 px-3.5 text-slate-900 font-medium">{ep.url_path}</td>
                      <td className="py-2.5 px-3.5">
                        {ep.auth_required ? (
                          <span className="text-amber-800 font-semibold flex items-center gap-1 text-[11px]">
                            <Lock className="h-3 w-3" /> Required
                          </span>
                        ) : (
                          <span className="text-slate-500">Public</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3.5">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-50 text-blue-800 border border-blue-200">
                          {ep.testing_status || "Discovered"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Tab 2: Domains */}
        {activeTab === "domains" && (
          <div>
            {domains.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-slate-500">
                No subdomains enumerated.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-50/50 text-slate-600 text-[10px] uppercase border-b border-slate-200 font-bold tracking-wider">
                  <tr>
                    <th className="py-2.5 px-3.5">FQDN</th>
                    <th className="py-2.5 px-3.5">Resolved IP(s)</th>
                    <th className="py-2.5 px-3.5">Discovery Source</th>
                    <th className="py-2.5 px-3.5">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {domains.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-50/70 transition-colors">
                      <td className="py-2.5 px-3.5 text-slate-900 font-bold">{d.fqdn}</td>
                      <td className="py-2.5 px-3.5 text-slate-700">
                        {Array.isArray(d.resolved_ips) ? d.resolved_ips.join(", ") : d.resolved_ips || "DNS Unresolved"}
                      </td>
                      <td className="py-2.5 px-3.5 text-slate-500">{d.discovery_source || "CRAWLER"}</td>
                      <td className="py-2.5 px-3.5">
                        <span className="text-emerald-700 font-semibold flex items-center gap-1 text-[11px]">
                          <CheckCircle2 className="h-3 w-3" /> Active
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Tab 3: Technologies */}
        {activeTab === "tech" && (
          <div>
            {technologies.length === 0 ? (
              <div className="p-8 text-center text-xs font-mono text-slate-500">
                No technologies fingerprinted yet.
              </div>
            ) : (
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-slate-50/50 text-slate-600 text-[10px] uppercase border-b border-slate-200 font-bold tracking-wider">
                  <tr>
                    <th className="py-2.5 px-3.5">Technology Component</th>
                    <th className="py-2.5 px-3.5">Detected Version</th>
                    <th className="py-2.5 px-3.5">Category</th>
                    <th className="py-2.5 px-3.5">Detection Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {technologies.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-50/70 transition-colors">
                      <td className="py-2.5 px-3.5 text-slate-900 font-bold">{t.name}</td>
                      <td className="py-2.5 px-3.5 text-blue-800 font-semibold">{t.version || "Unknown"}</td>
                      <td className="py-2.5 px-3.5 text-slate-600">{t.category}</td>
                      <td className="py-2.5 px-3.5 text-emerald-700 font-bold">{t.confidence || 100}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>

      {/* 6-Phase Linear Bottom Navigation */}
      <StepFooterNav
        currentStep={2}
        prevStepPath="/scope"
        prevStepLabel="Scope & RoE"
        nextStepPath="/wstg"
        nextStepLabel="Validate Surface & Continue to WSTG Plan"
        canAdvance={true}
      />
    </div>
  );
}
