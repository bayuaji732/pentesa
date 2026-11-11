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
  ExternalLink,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export default function DiscoveryPage() {
  const { currentProject } = useProject();
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
    } catch (err: any) {
      alert(`Crawl failed: ${err.message}`);
    } finally {
      setCrawling(false);
    }
  };

  if (!currentProject) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-500">
        Please select a project to view discovered attack surface.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Globe className="h-5 w-5 text-cyan-400" />
            Attack Surface Discovery & Inventory
          </h1>
          <p className="text-xs text-slate-400">
            Automated scope-enforced web crawling, endpoint inventory, and technology detection.
          </p>
        </div>
        <button
          onClick={loadData}
          className="p-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Crawl Control & Topology Overview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Topology Summary Cards */}
        <div className="lg:col-span-1 grid grid-cols-3 gap-2">
          <div className="bg-surface-base border border-slate-800 rounded-lg p-3 text-center">
            <Radio className="h-4 w-4 text-cyan-400 mx-auto mb-1" />
            <div className="text-xl font-bold font-mono text-slate-100">{domains.length}</div>
            <div className="text-[10px] text-slate-400 font-mono">Domains</div>
          </div>
          <div className="bg-surface-base border border-slate-800 rounded-lg p-3 text-center">
            <Layers className="h-4 w-4 text-emerald-400 mx-auto mb-1" />
            <div className="text-xl font-bold font-mono text-slate-100">{endpoints.length}</div>
            <div className="text-[10px] text-slate-400 font-mono">Endpoints</div>
          </div>
          <div className="bg-surface-base border border-slate-800 rounded-lg p-3 text-center">
            <Server className="h-4 w-4 text-amber-400 mx-auto mb-1" />
            <div className="text-xl font-bold font-mono text-slate-100">{technologies.length}</div>
            <div className="text-[10px] text-slate-400 font-mono">Tech Stack</div>
          </div>
        </div>

        {/* Crawler Launch Card */}
        <div className="lg:col-span-2 bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Play className="h-4 w-4 text-red-400 fill-current" />
              Automated Scope-Enforced Web Crawler
            </h3>
            {crawlSummary && (
              <span
                className={`text-[11px] font-mono ${
                  crawlSummary.endpoints_discovered === 0 && crawlSummary.errors?.length > 0
                    ? "text-amber-400"
                    : "text-emerald-400"
                }`}
              >
                Discovered: {crawlSummary.endpoints_discovered} endpoints, {crawlSummary.technologies_detected} technologies
              </span>
            )}
          </div>

          <form onSubmit={handleTriggerCrawl} className="flex flex-wrap items-center gap-3">
            <div className="flex-1 min-w-[220px] flex items-center gap-2 text-xs font-mono text-slate-300">
              <label className="shrink-0 text-slate-400">Target URL:</label>
              <input
                type="text"
                value={seedUrl}
                onChange={(e) => setSeedUrl(e.target.value)}
                placeholder="https://app.organization.com/ (auto-detect if blank)"
                className="w-full h-8 px-2.5 bg-slate-900 border border-slate-700 rounded text-slate-100 font-mono text-xs focus:outline-none focus:border-red-500"
              />
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
              <label className="text-slate-400">Depth:</label>
              <input
                type="number"
                min="1"
                max="5"
                value={maxDepth}
                onChange={(e) => setMaxDepth(parseInt(e.target.value) || 1)}
                className="w-14 h-8 px-2 bg-slate-900 border border-slate-700 rounded text-slate-100 font-mono text-center"
              />
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-slate-300">
              <label className="text-slate-400">Max Pages:</label>
              <input
                type="number"
                min="5"
                max="500"
                value={maxPages}
                onChange={(e) => setMaxPages(parseInt(e.target.value) || 10)}
                className="w-16 h-8 px-2 bg-slate-900 border border-slate-700 rounded text-slate-100 font-mono text-center"
              />
            </div>

            <button
              type="submit"
              disabled={crawling}
              className="px-4 h-8 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50 shrink-0"
            >
              {crawling ? (
                <>
                  <span className="h-3 w-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Crawling In-Scope Targets...
                </>
              ) : (
                <>
                  <Play className="h-3 w-3 fill-current" />
                  Start Crawler
                </>
              )}
            </button>
          </form>

          {crawlSummary?.errors && crawlSummary.errors.length > 0 && (
            <div className="p-2.5 rounded border border-amber-800/80 bg-amber-950/30 text-[11px] font-mono text-amber-300 space-y-1">
              <div className="font-semibold">
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
      <div className="bg-surface-base border border-slate-800 rounded-lg overflow-hidden">
        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-900/60 px-2 pt-2">
          <button
            onClick={() => setActiveTab("endpoints")}
            className={`px-4 py-2 text-xs font-mono font-semibold border-b-2 transition-all ${
              activeTab === "endpoints"
                ? "border-red-500 text-slate-100 bg-surface-base"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Discovered Endpoints ({endpoints.length})
          </button>
          <button
            onClick={() => setActiveTab("domains")}
            className={`px-4 py-2 text-xs font-mono font-semibold border-b-2 transition-all ${
              activeTab === "domains"
                ? "border-red-500 text-slate-100 bg-surface-base"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Subdomains ({domains.length})
          </button>
          <button
            onClick={() => setActiveTab("tech")}
            className={`px-4 py-2 text-xs font-mono font-semibold border-b-2 transition-all ${
              activeTab === "tech"
                ? "border-red-500 text-slate-100 bg-surface-base"
                : "border-transparent text-slate-400 hover:text-slate-200"
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
                <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Method</th>
                    <th className="py-2.5 px-3">Host</th>
                    <th className="py-2.5 px-3">URL Path</th>
                    <th className="py-2.5 px-3">Authentication</th>
                    <th className="py-2.5 px-3">Testing Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {endpoints.map((ep) => (
                    <tr key={ep.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            ep.http_method === "GET"
                              ? "bg-blue-950 text-blue-400 border border-blue-800"
                              : ep.http_method === "POST"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800"
                              : ep.http_method === "PUT"
                              ? "bg-amber-950 text-amber-400 border border-amber-800"
                              : "bg-red-950 text-red-400 border border-red-800"
                          }`}
                        >
                          {ep.http_method}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300 font-bold">{ep.fqdn}</td>
                      <td className="py-2.5 px-3 text-slate-100">{ep.url_path}</td>
                      <td className="py-2.5 px-3">
                        {ep.auth_required ? (
                          <span className="text-amber-400 flex items-center gap-1 text-[11px]">
                            <Lock className="h-3 w-3" /> Required
                          </span>
                        ) : (
                          <span className="text-slate-500">Public</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-cyan-400 font-semibold">{ep.testing_status || "Discovered"}</span>
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
                <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">FQDN</th>
                    <th className="py-2.5 px-3">Resolved IP(s)</th>
                    <th className="py-2.5 px-3">Discovery Source</th>
                    <th className="py-2.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {domains.map((d) => (
                    <tr key={d.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3 text-slate-100 font-bold">{d.fqdn}</td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {Array.isArray(d.resolved_ips) ? d.resolved_ips.join(", ") : d.resolved_ips || "DNS Unresolved"}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{d.discovery_source || "CRAWLER"}</td>
                      <td className="py-2.5 px-3">
                        <span className="text-emerald-400 flex items-center gap-1 text-[11px]">
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
                <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Technology Component</th>
                    <th className="py-2.5 px-3">Detected Version</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Detection Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {technologies.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3 text-slate-100 font-bold">{t.name}</td>
                      <td className="py-2.5 px-3 text-cyan-400 font-semibold">{t.version || "Unknown"}</td>
                      <td className="py-2.5 px-3 text-slate-400">{t.category}</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">{t.confidence || 100}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

