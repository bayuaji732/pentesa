"use client";

import React, { useEffect, useState } from "react";
import {
  Bot,
  Play,
  Pause,
  Square,
  Cpu,
  BrainCircuit,
  Terminal,
  Activity,
  CheckCircle2,
  Clock,
  RefreshCw,
  Coins,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

export default function AgentsPage() {
  const { currentProject } = useProject();
  const [workflow, setWorkflow] = useState<any>(null);
  const [decisions, setDecisions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [scanProfile, setScanProfile] = useState<"QUICK" | "FULL" | "DEEP">("QUICK");

  const loadData = async () => {
    if (!currentProject) return;
    setLoading(true);
    try {
      const [wf, decs] = await Promise.allSettled([
        api.getWorkflowStatus(currentProject.id),
        api.getAgentDecisions(currentProject.id),
      ]);
      if (wf.status === "fulfilled") setWorkflow(wf.value);
      if (decs.status === "fulfilled") setDecisions(decs.value);
    } catch (err) {
      console.error("Agents load error", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // Poll every 3s if running
    const interval = setInterval(() => {
      if (workflow?.status === "RUNNING") {
        loadData();
      }
    }, 3000);
    return () => clearInterval(interval);
  }, [currentProject, workflow?.status]);

  const handleStart = async () => {
    if (!currentProject) return;
    setActionLoading(true);
    try {
      const res = await api.startWorkflow(currentProject.id, true, scanProfile);
      setWorkflow(res);
      await loadData();
    } catch (err: any) {
      alert(`Start failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleReset = async () => {
    if (!currentProject) return;
    setActionLoading(true);
    try {
      const res = await api.resetWorkflow(currentProject.id);
      setWorkflow(res);
      await loadData();
    } catch (err: any) {
      alert(`Reset failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handlePause = async () => {
    if (!currentProject) return;
    setActionLoading(true);
    try {
      const res = await api.pauseWorkflow(currentProject.id);
      setWorkflow(res);
    } catch (err: any) {
      alert(`Pause failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleResume = async () => {
    if (!currentProject) return;
    setActionLoading(true);
    try {
      const res = await api.resumeWorkflow(currentProject.id);
      setWorkflow(res);
    } catch (err: any) {
      alert(`Resume failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    if (!currentProject) return;
    if (!confirm("Are you sure you want to emergency abort the active pentest workflow?")) return;
    setActionLoading(true);
    try {
      const res = await api.stopWorkflow(currentProject.id);
      setWorkflow(res);
    } catch (err: any) {
      alert(`Stop failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  if (!currentProject) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-500">
        Please select a project to view autonomous multi-agent orchestrator.
      </div>
    );
  }

  const agentsList = workflow?.active_agents || [
    { agent_id: "planner", agent_name: "Project Planning Agent", phase: "MAPPING", status: "STANDBY" },
    { agent_id: "recon", agent_name: "Reconnaissance Agent", phase: "RECON", status: "STANDBY" },
    { agent_id: "wstg", agent_name: "WSTG Assessment Agent", phase: "WSTG_PLANNING", status: "STANDBY" },
    { agent_id: "vuln", agent_name: "Vulnerability Agent", phase: "ACTIVE_ASSESSMENT", status: "STANDBY" },
    { agent_id: "authz", agent_name: "Authorization Agent", phase: "ACTIVE_ASSESSMENT", status: "STANDBY" },
    { agent_id: "validation", agent_name: "Validation Agent", phase: "VALIDATION", status: "STANDBY" },
    { agent_id: "reporting", agent_name: "Reporting Agent", phase: "REPORTING", status: "STANDBY" },
  ];

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Bot className="h-5 w-5 text-cyan-400" />
            Autonomous Multi-Agent DAG Orchestrator
          </h1>
          <p className="text-xs text-slate-400">
            Hierarchical LangGraph supervision across 15 specialized agents with real-time thought trace auditing.
          </p>
        </div>

        {/* Workflow Actions & Scan Profile */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Scan Profile Selector */}
          <div className="flex items-center rounded border border-slate-700 bg-slate-900 p-0.5 text-xs font-mono">
            <button
              onClick={() => setScanProfile("QUICK")}
              className={`px-2.5 py-1 rounded transition-colors ${
                scanProfile === "QUICK"
                  ? "bg-cyan-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Quick Scan (Smoke Test, ~3s)"
            >
              ⚡ Quick Scan
            </button>
            <button
              onClick={() => setScanProfile("FULL")}
              className={`px-2.5 py-1 rounded transition-colors ${
                scanProfile === "FULL"
                  ? "bg-cyan-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Full Scan (Standard OWASP WSTG, ~30s)"
            >
              🛡️ Full Scan
            </button>
            <button
              onClick={() => setScanProfile("DEEP")}
              className={`px-2.5 py-1 rounded transition-colors ${
                scanProfile === "DEEP"
                  ? "bg-cyan-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Deep Scan (Exhaustive Fuzzing, ~90s)"
            >
              🔬 Deep Scan
            </button>
          </div>

          {workflow?.status === "RUNNING" ? (
            <>
              <button
                onClick={handlePause}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Pause className="h-3.5 w-3.5" /> Pause
              </button>
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Square className="h-3.5 w-3.5" /> Stop
              </button>
            </>
          ) : workflow?.status === "PAUSED" ? (
            <>
              <button
                onClick={handleResume}
                disabled={actionLoading}
                className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Play className="h-3.5 w-3.5 fill-current" /> Resume DAG
              </button>
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Square className="h-3.5 w-3.5" /> Stop
              </button>
            </>
          ) : (
            <button
              onClick={handleStart}
              disabled={actionLoading}
              className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-lg shadow-red-950/40"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              {actionLoading ? "Starting Swarm..." : "Start Swarm"}
            </button>
          )}

          {/* Reset button if failed or stuck */}
          {workflow?.status && ["FAILED", "STOPPED", "INTERRUPTED", "RUNNING"].includes(workflow.status) && (
            <button
              onClick={handleReset}
              disabled={actionLoading}
              title="Reset workflow to clean state"
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-mono transition-colors"
            >
              Reset
            </button>
          )}

          <button
            onClick={loadData}
            title="Refresh Swarm Status"
            className="p-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Workflow Phase Pipeline */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400">Current Phase: <strong className="text-cyan-400">{workflow?.current_phase || "IDLE / READY"}</strong></span>
          <span className="text-slate-400">Status: <strong className="text-slate-200">{workflow?.status || "STANDBY"}</strong></span>
        </div>

        {/* Phase Pipeline Breadcrumbs */}
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-center text-[11px] font-mono">
          {["RECON", "MAPPING", "WSTG_PLANNING", "ACTIVE_ASSESSMENT", "VALIDATION", "REPORTING"].map((phase, idx) => {
            const isCurrent = workflow?.current_phase === phase;
            return (
              <div
                key={phase}
                className={`p-2 rounded border transition-all ${
                  isCurrent
                    ? "bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold shadow-lg shadow-cyan-950/50"
                    : "bg-slate-900/60 border-slate-800 text-slate-400"
                }`}
              >
                <div className="text-[10px] text-slate-500">Step {idx + 1}</div>
                <div className="truncate">{phase}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Agents Telemetry Table */}
      <div className="bg-surface-base border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            Specialized Security Agents ({agentsList.length})
          </h3>
          <span className="text-[10px] font-mono text-slate-500">Live Agent Telemetry & LLM Tokens</span>
        </div>

        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Agent Name</th>
              <th className="py-2.5 px-3">Operational Phase</th>
              <th className="py-2.5 px-3">State</th>
              <th className="py-2.5 px-3">Tokens (In / Out)</th>
              <th className="py-2.5 px-3">Decisions</th>
              <th className="py-2.5 px-3">Tools Dispatched</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {agentsList.map((a: any) => (
              <tr key={a.agent_id || a.agent_name} className="hover:bg-slate-800/30 transition-colors">
                <td className="py-2.5 px-3 text-slate-100 font-bold font-sans flex items-center gap-2">
                  <Bot className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
                  {a.agent_name}
                </td>
                <td className="py-2.5 px-3 text-slate-400 text-[11px]">{a.phase}</td>
                <td className="py-2.5 px-3">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      a.status === "COMPLETED"
                        ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                        : a.status === "RUNNING"
                        ? "bg-cyan-950 text-cyan-400 border-cyan-800"
                        : "bg-slate-800 text-slate-300 border-slate-700"
                    }`}
                  >
                    {a.status || "STANDBY"}
                  </span>
                </td>
                <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                  {a.prompt_tokens || 0} / {a.completion_tokens || 0}
                </td>
                <td className="py-2.5 px-3 text-cyan-400 font-bold">{a.decisions_count || 0}</td>
                <td className="py-2.5 px-3 text-slate-300">{a.tool_calls_count || 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Agent Thought Trace & Decision Feed */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BrainCircuit className="h-4 w-4 text-purple-400" />
            <h3 className="text-sm font-semibold text-slate-200">Real-Time Agent Thought Trace & Decisions</h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">Autonomous Reasoning Audit Log</span>
        </div>

        {decisions.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500 border border-slate-800/80 rounded bg-slate-900/40">
            No agent decisions recorded yet. Start the autonomous workflow to stream thought traces.
          </div>
        ) : (
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {decisions.map((d) => (
              <div
                key={d.id}
                className="p-3 bg-slate-900/80 border border-slate-800 rounded-md space-y-1 font-mono text-xs"
              >
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-cyan-400 font-bold">{d.agent_name || "Specialized Agent"}</span>
                  <span className="text-slate-500">{new Date(d.created_at).toLocaleTimeString()}</span>
                </div>
                <div className="text-slate-200 font-sans text-xs">{d.thought_trace}</div>
                <div className="flex items-center gap-4 text-[11px] pt-1 text-slate-400 border-t border-slate-800/60">
                  <span>Intent: <strong className="text-slate-300">{d.intent}</strong></span>
                  <span>Confidence: <strong className="text-emerald-400">{d.confidence || "High"}</strong></span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

