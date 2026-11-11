"use client";

import React, { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useProject, Project } from "@/lib/ProjectContext";
import { api } from "@/lib/api";
import {
  Layers,
  ShieldCheck,
  Plus,
  Search,
  Calendar,
  Globe,
  Clock,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Trash2,
  ExternalLink,
  Lock,
} from "lucide-react";

export default function ProjectsPage() {
  const router = useRouter();
  const { currentProject, projects, setCurrentProject, refreshProjects, loading } = useProject();

  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // New Project Form State
  const getInitialForm = () => {
    const startIso = new Date().toISOString().slice(0, 16);
    const endIso = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 16);
    return {
      name: "",
      description: "",
      target_domains: "",
      allowed_cidrs: "",
      excluded_paths: "",
      allow_internal_networks: false,
      authorization_document_ref: "",
      authorization_start: startIso,
      authorization_end: endIso,
    };
  };

  const [form, setForm] = useState(getInitialForm);

  const handleSelectProject = (proj: Project) => {
    setCurrentProject(proj);
  };

  const handleDeleteProject = async (proj: Project) => {
    if (!confirm(`Delete engagement "${proj.name}"? This removes all project targets, scans, and findings.`)) {
      return;
    }
    try {
      await api.deleteProject(proj.id);
      await refreshProjects();
    } catch (err: any) {
      alert("Project deletion failed: " + (err?.message || "Error"));
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const targetDomainsList = form.target_domains
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const allowedCidrsList = form.allowed_cidrs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const excludedPathsList = form.excluded_paths
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const created = await api.createProject({
        name: form.name,
        description: form.description,
        target_domains: targetDomainsList,
        allowed_cidrs: allowedCidrsList,
        excluded_paths: excludedPathsList,
        allow_internal_networks: form.allow_internal_networks,
        authorization_document_ref: form.authorization_document_ref,
        authorization_start: new Date(form.authorization_start).toISOString(),
        authorization_end: new Date(form.authorization_end).toISOString(),
      });

      await refreshProjects();
      setCurrentProject(created);
      setForm(getInitialForm());
      setCreateModalOpen(false);
      alert("Engagement project created successfully!");
    } catch (err: any) {
      alert("Project creation failed: " + (err?.message || "Error"));
    } finally {
      setSubmitting(false);
    }
  };

  const filteredProjects = projects.filter((p) => {
    if (statusFilter !== "ALL" && p.status?.toUpperCase() !== statusFilter.toUpperCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = p.name?.toLowerCase().includes(q);
      const matchDesc = p.description?.toLowerCase().includes(q);
      const matchDomains = p.target_domains?.some((d) => d.toLowerCase().includes(q));
      if (!matchName && !matchDesc && !matchDomains) return false;
    }
    return true;
  });

  const getStatusBadge = (status: string) => {
    const s = status?.toUpperCase();
    if (s === "ACTIVE" || s === "IN_PROGRESS") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          ACTIVE ENGAGEMENT
        </span>
      );
    }
    if (s === "PLANNING") {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
          PLANNING
        </span>
      );
    }
    if (s === "COMPLETED") {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
          COMPLETED
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
        {status || "UNKNOWN"}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-100">Penetration Testing Engagements</h1>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              {projects.length} Total
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Manage target authorizations, Rules of Engagement (RoE) validation windows, and multi-tenant perimeters.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              setForm(getInitialForm());
              setCreateModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-xs font-semibold text-white transition-colors shadow-lg shadow-red-950/40"
          >
            <Plus className="h-3.5 w-3.5" />
            New Engagement
          </button>
          <button
            onClick={refreshProjects}
            disabled={loading}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700"
            title="Refresh projects"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-surface-base p-3 rounded border border-slate-800">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search engagement, domain, client..."
            className="w-full bg-surface-elevated pl-9 pr-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 placeholder-slate-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          {["ALL", "PLANNING", "ACTIVE", "COMPLETED"].map((tab) => (
            <button
              key={tab}
              onClick={() => setStatusFilter(tab)}
              className={`px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors ${
                statusFilter === tab
                  ? "bg-slate-800 text-slate-100 border border-slate-600 font-bold"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Projects Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          [1, 2, 3].map((i) => (
            <div key={i} className="h-48 bg-surface-base border border-slate-800 rounded animate-pulse" />
          ))
        ) : filteredProjects.length === 0 ? (
          <div className="col-span-full p-12 text-center bg-surface-base border border-slate-800 rounded">
            <Layers className="h-10 w-10 text-slate-600 mx-auto mb-3" />
            <p className="text-sm font-semibold text-slate-200">No engagement projects found</p>
            <p className="text-xs text-slate-500 mt-1">
              Click &quot;+ New Engagement&quot; to authorize and register your first target perimeter.
            </p>
          </div>
        ) : (
          filteredProjects.map((proj) => {
            const isSelected = currentProject?.id === proj.id;

            return (
              <div
                key={proj.id}
                className={`p-5 rounded border transition-all flex flex-col justify-between space-y-4 ${
                  isSelected
                    ? "bg-surface-elevated border-red-500 shadow-lg shadow-red-950/20"
                    : "bg-surface-base border-slate-800 hover:border-slate-700 hover:bg-surface-elevated/60"
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    {getStatusBadge(proj.status)}
                    {isSelected && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/70 text-red-400 border border-red-800 font-bold">
                        ACTIVE CONTEXT
                      </span>
                    )}
                  </div>

                  <div>
                    <h3 className="text-base font-bold text-slate-100">{proj.name}</h3>
                    <p className="text-xs text-slate-400 line-clamp-2 mt-1">{proj.description}</p>
                  </div>

                  {/* Target Domains */}
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold flex items-center gap-1">
                      <Globe className="h-3 w-3 text-cyan-400" /> Target Domains ({proj.target_domains?.length || 0})
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {proj.target_domains?.slice(0, 3).map((d) => (
                        <span
                          key={d}
                          className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-300"
                        >
                          {d}
                        </span>
                      ))}
                      {(proj.target_domains?.length || 0) > 3 && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-slate-500">
                          +{(proj.target_domains?.length || 0) - 3} more
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Authorization Dates */}
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 flex items-center gap-1">
                        <Calendar className="h-3 w-3 text-slate-400" /> RoE Window:
                      </span>
                      <span className="text-slate-300">
                        {new Date(proj.authorization_start).toLocaleDateString()} →{" "}
                        {new Date(proj.authorization_end).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono text-slate-500">
                    Created {new Date(proj.created_at).toLocaleDateString()}
                  </span>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleDeleteProject(proj)}
                      title="Delete engagement project"
                      className="p-1.5 rounded bg-slate-900 hover:bg-red-950 text-slate-500 hover:text-red-400 border border-slate-800 hover:border-red-800 transition-colors"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                    {isSelected ? (
                      <button
                        onClick={() => router.push("/")}
                        className="flex items-center gap-1 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 border border-slate-700 transition-colors"
                      >
                        Open Dashboard <ArrowRight className="h-3 w-3" />
                      </button>
                    ) : (
                      <button
                        onClick={() => handleSelectProject(proj)}
                        className="flex items-center gap-1 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-400 border border-cyan-900 transition-colors"
                      >
                        Switch to Project
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Create Project Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-surface-base border border-slate-800 rounded-lg max-w-xl w-full p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-red-500" />
                <h3 className="text-base font-bold text-slate-100">Authorize New Engagement</h3>
              </div>
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="text-slate-500 hover:text-slate-300 font-mono"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 max-h-[70vh] overflow-y-auto pr-1">
              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Engagement Name *</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g. Q4 Web Application Security Assessment"
                  className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">Description</label>
                <textarea
                  rows={2}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Scope objectives, emergency escalations, compliance goals..."
                  className="w-full bg-surface-elevated p-2.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">
                  Target In-Scope Domains * (comma-separated)
                </label>
                <input
                  type="text"
                  required
                  value={form.target_domains}
                  onChange={(e) => setForm({ ...form, target_domains: e.target.value })}
                  placeholder="app.organization.com, api.organization.com"
                  className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Allowed CIDRs</label>
                  <input
                    type="text"
                    value={form.allowed_cidrs}
                    onChange={(e) => setForm({ ...form, allowed_cidrs: e.target.value })}
                    placeholder="10.0.0.0/24"
                    className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Excluded Paths</label>
                  <input
                    type="text"
                    value={form.excluded_paths}
                    onChange={(e) => setForm({ ...form, excluded_paths: e.target.value })}
                    placeholder="/logout, /internal/reset"
                    className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono text-slate-300 mb-1">RoE Authorization Document Ref *</label>
                <input
                  type="text"
                  required
                  value={form.authorization_document_ref}
                  onChange={(e) => setForm({ ...form, authorization_document_ref: e.target.value })}
                  placeholder="ROE-YYYY-ORG-001"
                  className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Authorization Start *</label>
                  <input
                    type="datetime-local"
                    required
                    value={form.authorization_start}
                    onChange={(e) => setForm({ ...form, authorization_start: e.target.value })}
                    className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-mono text-slate-300 mb-1">Authorization End *</label>
                  <input
                    type="datetime-local"
                    required
                    value={form.authorization_end}
                    onChange={(e) => setForm({ ...form, authorization_end: e.target.value })}
                    className="w-full bg-surface-elevated px-3 py-1.5 rounded text-xs text-slate-200 border border-slate-700 focus:outline-none focus:border-red-500 font-mono"
                  />
                </div>
              </div>

              <div className="pt-1">
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.allow_internal_networks}
                    onChange={(e) => setForm({ ...form, allow_internal_networks: e.target.checked })}
                    className="rounded bg-surface-elevated border-slate-700 text-red-600 focus:ring-0"
                  />
                  <span>Allow Testing of RFC1918 Private Internal Networks</span>
                </label>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 font-mono"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-1.5 rounded bg-red-600 hover:bg-red-500 disabled:opacity-50 text-xs font-semibold text-white font-mono"
              >
                {submitting ? "Authorizing..." : "Authorize Engagement"}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
