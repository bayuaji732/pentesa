"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useProject, Project } from "@/lib/ProjectContext";
import { useToast } from "@/lib/ToastContext";
import { api } from "@/lib/api";
import {
  Layers,
  ShieldCheck,
  Plus,
  Search,
  Calendar,
  Globe,
  ArrowRight,
  RefreshCw,
  Trash2,
} from "lucide-react";

export default function ProjectsPage() {
  const router = useRouter();
  const { currentProject, projects, setCurrentProject, refreshProjects, loading } = useProject();
  const { toast, confirmDialog } = useToast();

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

  const handleOpenEngagement = (proj: Project) => {
    setCurrentProject(proj);
    const status = proj.status?.toUpperCase();
    if (status === "COMPLETED") {
      router.push("/reports");
    } else if (status === "ACTIVE" || status === "IN_PROGRESS") {
      router.push("/agents");
    } else {
      router.push("/scope");
    }
  };

  const handleDeleteProject = async (proj: Project) => {
    const ok = await confirmDialog({
      title: "Delete Authorized Engagement",
      message: `Permanently delete "${proj.name}"? This removes all associated target perimeters, scan execution histories, and discovered findings.`,
      confirmText: "Delete Engagement",
      isDestructive: true,
    });
    if (!ok) return;

    try {
      await api.deleteProject(proj.id);
      await refreshProjects();
      toast.success(`Engagement "${proj.name}" deleted.`);
    } catch (err: any) {
      toast.error("Engagement deletion failed: " + (err?.message || "Error"));
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
      toast.success("Engagement authorized successfully! Entering Step 1: Scope & Boundaries.");
      router.push("/scope");
    } catch (err: any) {
      toast.error("Engagement authorization failed: " + (err?.message || "Error"));
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
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-50 text-emerald-800 border border-emerald-200">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
          ACTIVE ENGAGEMENT
        </span>
      );
    }
    if (s === "PLANNING") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-blue-50 text-blue-800 border border-blue-200">
          <span className="h-1.5 w-1.5 rounded-full bg-blue-600" />
          PLANNING
        </span>
      );
    }
    if (s === "COMPLETED") {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
          <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
          COMPLETED
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
        {status || "UNKNOWN"}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold tracking-tight text-slate-900">Penetration Testing Engagements</h1>
            <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              {projects.length} Total
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Manage target authorizations, Rules of Engagement (RoE) validation windows, and multi-tenant perimeters.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              setForm(getInitialForm());
              setCreateModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-md bg-blue-900 hover:bg-blue-800 text-xs font-semibold text-white shadow-xs transition-colors cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" />
            New Engagement
          </button>
          <button
            onClick={refreshProjects}
            disabled={loading}
            className="p-2 rounded-md bg-white hover:bg-slate-50 text-slate-600 hover:text-slate-900 border border-slate-200 shadow-xs transition-colors"
            title="Refresh engagements"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin text-blue-700" : ""}`} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3 items-center justify-between bg-white p-3 rounded-xl border border-slate-200 shadow-xs">
        <div className="relative w-full sm:w-80">
          <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search engagement, domain, client..."
            className="w-full bg-slate-50 pl-9 pr-3 py-1.5 rounded-md text-xs text-slate-900 border border-slate-200 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-sans transition-all"
          />
        </div>

        <div className="flex items-center gap-1.5 w-full sm:w-auto">
          {["ALL", "PLANNING", "ACTIVE", "COMPLETED"].map((tab) => (
            <button
              key={tab}
              onClick={() => setStatusFilter(tab)}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-colors ${
                statusFilter === tab
                  ? "bg-blue-900 text-white font-bold shadow-xs"
                  : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Engagements Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {loading ? (
          [1, 2, 3].map((i) => (
            <div key={i} className="h-48 bg-white border border-slate-200 rounded-xl animate-pulse shadow-xs" />
          ))
        ) : filteredProjects.length === 0 ? (
          <div className="col-span-full p-12 text-center bg-white border border-slate-200 rounded-xl shadow-xs">
            <Layers className="h-10 w-10 text-slate-400 mx-auto mb-3" />
            <p className="text-sm font-bold text-slate-900">No engagements found</p>
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
                onClick={() => handleOpenEngagement(proj)}
                className={`p-5 rounded-xl border transition-all flex flex-col justify-between space-y-4 shadow-xs cursor-pointer group ${
                  isSelected
                    ? "bg-blue-50/20 border-blue-600 ring-2 ring-blue-600/20 hover:border-blue-700"
                    : "bg-white border-slate-200 hover:border-blue-400 hover:shadow-md"
                }`}
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-2">
                    {getStatusBadge(proj.status)}
                    {isSelected && (
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-50 text-blue-900 border border-blue-200 font-bold">
                        ACTIVE CONTEXT
                      </span>
                    )}
                  </div>

                  <div>
                    <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-900 transition-colors">
                      {proj.name}
                    </h3>
                    <p className="text-xs text-slate-600 line-clamp-2 mt-1 leading-normal">{proj.description}</p>
                  </div>

                  {/* Target Domains */}
                  <div className="space-y-1">
                    <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold flex items-center gap-1">
                      <Globe className="h-3 w-3 text-blue-700" /> Target Domains ({proj.target_domains?.length || 0})
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {proj.target_domains?.slice(0, 3).map((d) => (
                        <span
                          key={d}
                          className="px-2 py-0.5 rounded bg-slate-50 border border-slate-200 text-[10px] font-mono text-slate-800"
                        >
                          {d}
                        </span>
                      ))}
                      {(proj.target_domains?.length || 0) > 3 && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-50 border border-slate-200 text-[10px] font-mono text-slate-500">
                          +{(proj.target_domains?.length || 0) - 3} more
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Authorization Dates */}
                  <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] font-mono text-slate-600 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-500 flex items-center gap-1">
                        <Calendar className="h-3 w-3 text-slate-400" /> RoE Window:
                      </span>
                      <span className="text-slate-800 font-semibold">
                        {new Date(proj.authorization_start).toLocaleDateString()} →{" "}
                        {new Date(proj.authorization_end).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-100 flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono text-slate-400">
                    Created {new Date(proj.created_at).toLocaleDateString()}
                  </span>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteProject(proj);
                      }}
                      title="Delete engagement"
                      className="p-1.5 rounded-md bg-white hover:bg-rose-50 text-slate-400 hover:text-rose-600 border border-slate-200 hover:border-rose-200 transition-colors"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                    <Link
                      href="/"
                      onClick={(e) => {
                        e.stopPropagation();
                        setCurrentProject(proj);
                      }}
                      className="text-xs font-semibold text-slate-600 hover:text-blue-900 px-2 py-1.5 rounded hover:bg-slate-100 transition-colors"
                      title="View Executive Overview & Metrics"
                    >
                      Overview
                    </Link>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleOpenEngagement(proj);
                      }}
                      className="flex items-center gap-1 px-3 py-1.5 rounded-md bg-blue-900 hover:bg-blue-800 text-xs font-semibold text-white shadow-xs transition-colors"
                    >
                      <span>Open</span>
                      <ArrowRight className="h-3.5 w-3.5 group-hover:translate-x-0.5 transition-transform" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Create Project Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreate}
            className="bg-white border border-slate-200 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-xl"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-blue-900" />
                <h3 className="text-base font-bold text-slate-900">Authorize New Engagement</h3>
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
                <label className="block text-xs font-semibold text-slate-700 mb-1">Engagement Name *</label>
                <input
                  type="text"
                  required
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="e.g. Q4 Web Application Security Assessment"
                  className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 transition-all"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">Description</label>
                <textarea
                  rows={2}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                  placeholder="Scope objectives, emergency escalations, compliance goals..."
                  className="w-full bg-white p-2.5 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 transition-all font-sans"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Target In-Scope Domains * (comma-separated)
                </label>
                <input
                  type="text"
                  required
                  value={form.target_domains}
                  onChange={(e) => setForm({ ...form, target_domains: e.target.value })}
                  placeholder="app.organization.com, api.organization.com"
                  className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-mono transition-all"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Allowed CIDRs</label>
                  <input
                    type="text"
                    value={form.allowed_cidrs}
                    onChange={(e) => setForm({ ...form, allowed_cidrs: e.target.value })}
                    placeholder="10.0.0.0/24"
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-mono transition-all"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Excluded Paths</label>
                  <input
                    type="text"
                    value={form.excluded_paths}
                    onChange={(e) => setForm({ ...form, excluded_paths: e.target.value })}
                    placeholder="/logout, /internal/reset"
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-mono transition-all"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">RoE Authorization Document Ref *</label>
                <input
                  type="text"
                  required
                  value={form.authorization_document_ref}
                  onChange={(e) => setForm({ ...form, authorization_document_ref: e.target.value })}
                  placeholder="ROE-YYYY-ORG-001"
                  className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 placeholder:text-slate-400 font-mono transition-all"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Authorization Start *</label>
                  <input
                    type="datetime-local"
                    required
                    value={form.authorization_start}
                    onChange={(e) => setForm({ ...form, authorization_start: e.target.value })}
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono transition-all"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">Authorization End *</label>
                  <input
                    type="datetime-local"
                    required
                    value={form.authorization_end}
                    onChange={(e) => setForm({ ...form, authorization_end: e.target.value })}
                    className="w-full bg-white px-3 py-2 rounded-md text-xs text-slate-900 border border-slate-300 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15 font-mono transition-all"
                  />
                </div>
              </div>

              <div className="pt-1">
                <label className="flex items-center gap-2 text-xs text-slate-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.allow_internal_networks}
                    onChange={(e) => setForm({ ...form, allow_internal_networks: e.target.checked })}
                    className="rounded border-slate-300 text-blue-900 focus:ring-blue-600"
                  />
                  <span>Allow Testing of RFC1918 Private Internal Networks</span>
                </label>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-100 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-4 py-2 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-xs font-medium text-slate-700 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 rounded-md bg-blue-900 hover:bg-blue-800 disabled:opacity-50 text-xs font-semibold text-white shadow-xs transition-colors"
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
