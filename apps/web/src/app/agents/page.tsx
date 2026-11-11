"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bot,
  Play,
  Pause,
  Square,
  Cpu,
  BrainCircuit,
  Wrench,
  CheckCircle2,
  Clock,
  RefreshCw,
  Coins,
  ShieldAlert,
  AlertCircle,
  RotateCcw,
  Check,
  X,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { api } from "@/lib/api";

const WORKFLOW_PHASES = [
  "PLANNING",
  "RECON",
  "WSTG_PLANNING",
  "ACTIVE_ASSESSMENT",
  "VALIDATION",
  "REPORTING",
] as const;

const STANDBY_AGENTS = [
  { agent_id: "AGT-01", agent_name: "Project Planning Agent", phase: "PLANNING", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-03", agent_name: "Reconnaissance & Surface Mapping Agent", phase: "RECON", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-05", agent_name: "WSTG Assessment Agent", phase: "WSTG_PLANNING", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-09", agent_name: "Vulnerability Detection Agent", phase: "ACTIVE_ASSESSMENT", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-07", agent_name: "Authorization Testing Agent", phase: "ACTIVE_ASSESSMENT", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-11", agent_name: "Vulnerability Validation & Quality Control Agent", phase: "VALIDATION", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-15", agent_name: "PTES Reporting Agent", phase: "REPORTING", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
];

function formatTraceContent(raw: string): { isJson: boolean; formatted: string } {
  const trimmed = (raw || "").trim();
  if (!trimmed) return { isJson: false, formatted: "(No reasoning trace captured)" };
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      return { isJson: true, formatted: JSON.stringify(parsed, null, 2) };
    } catch {
      return { isJson: false, formatted: trimmed };
    }
  }
  return { isJson: false, formatted: trimmed };
}

export default function AgentsPage() {
  const { currentProject } = useProject();
  const [workflow, setWorkflow] = useState<any>(null);
  const [decisions, setDecisions] = useState<any[]>([]);
  const [toolCalls, setToolCalls] = useState<any[]>([]);
  const [approvals, setApprovals] = useState<any[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [scanProfile, setScanProfile] = useState<"QUICK" | "FULL" | "DEEP">("QUICK");
  const [autoApproveMedium, setAutoApproveMedium] = useState<boolean>(true);
  const [selectedAgentFilter, setSelectedAgentFilter] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"decisions" | "tools">("decisions");
  const [banner, setBanner] = useState<{ type: "info" | "success" | "error"; text: string } | null>(null);
  const [justificationText, setJustificationText] = useState("");
  const prevStatusRef = useRef<string | null>(null);

  const loadData = useCallback(async (isPoll = false) => {
    if (!currentProject) return;
    if (!isPoll) setRefreshing(true);

    try {
      const [wf, decs, tools, apps] = await Promise.allSettled([
        api.getWorkflowStatus(currentProject.id),
        api.getAgentDecisions(currentProject.id, selectedAgentFilter || undefined),
        api.getAgentToolCalls(currentProject.id, selectedAgentFilter || undefined),
        api.listApprovals(currentProject.id),
      ]);

      if (wf.status === "fulfilled") {
        setWorkflow(wf.value);
      } else {
        // 404 before first workflow launch -> treat cleanly as standby
        setWorkflow(null);
      }
      if (decs.status === "fulfilled") setDecisions(decs.value);
      if (tools.status === "fulfilled") setToolCalls(tools.value);
      if (apps.status === "fulfilled") setApprovals(apps.value);
    } catch (err) {
      console.error("Agents load error", err);
    } finally {
      setInitialLoading(false);
      setRefreshing(false);
    }
  }, [currentProject, selectedAgentFilter]);

  useEffect(() => {
    setBanner(null);
    setSelectedAgentFilter(null);
    prevStatusRef.current = null;
  }, [currentProject?.id]);

  useEffect(() => {
    setInitialLoading(true);
    loadData(false);
  }, [loadData]);

  // Real-time fast polling while workflow is active (RUNNING, PAUSED, WAITING_APPROVAL)
  useEffect(() => {
    if (!currentProject) return;
    const status = workflow?.status;
    if (prevStatusRef.current && prevStatusRef.current !== status && !["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(status || "")) {
      // Final sync after transition to COMPLETED / FAILED / STOPPED
      loadData(true);
      if (status === "COMPLETED") {
        setBanner({
          type: "success",
          text: `${workflow?.state_data?.scan_profile || scanProfile} workflow completed — all agent telemetry and traces synced.`,
        });
      } else if (status === "FAILED") {
        setBanner({
          type: "error",
          text: `Workflow failed: ${workflow?.state_data?.error || "Unhandled execution error"}`,
        });
      }
    } else if (prevStatusRef.current === "RUNNING" && status === "WAITING_APPROVAL") {
      loadData(true);
      setBanner({
        type: "info",
        text: "Workflow paused at Human-in-the-Loop Approval Gate — approve or reject the pending action below.",
      });
    }
    prevStatusRef.current = status || null;

    if (!status || !["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(status)) {
      return;
    }

    const interval = setInterval(() => {
      loadData(true);
    }, 1500);
    return () => clearInterval(interval);
  }, [currentProject, workflow?.status, workflow?.state_data?.scan_profile, workflow?.state_data?.error, scanProfile, loadData]);

  const handleStart = async () => {
    if (!currentProject) return;
    setActionLoading(true);
    setBanner(null);
    try {
      const res = await api.startWorkflow(currentProject.id, autoApproveMedium, scanProfile, true);
      setWorkflow(res);
      setBanner({
        type: "info",
        text: `Launched ${scanProfile} multi-agent swarm (async streaming active)...`,
      });
      await loadData(true);
    } catch (err: any) {
      setBanner({ type: "error", text: `Start failed: ${err.message}` });
    } finally {
      setActionLoading(false);
    }
  };

  const handleReset = async () => {
    if (!currentProject) return;
    setActionLoading(true);
    setBanner(null);
    try {
      const res = await api.resetWorkflow(currentProject.id);
      if (res && Array.isArray(res.active_agents) && res.active_agents.length > 0) {
        setWorkflow(res);
      } else {
        await loadData(false);
      }
      setBanner({ type: "info", text: "Workflow state reset cleanly. Ready for new scan launch." });
    } catch (err: any) {
      setBanner({ type: "error", text: `Reset failed: ${err.message}` });
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
      setBanner({ type: "info", text: `Workflow paused at phase ${res.current_phase}. Click Resume DAG to continue.` });
    } catch (err: any) {
      setBanner({ type: "error", text: `Pause failed: ${err.message}` });
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
      setBanner({ type: "info", text: `Resumed workflow execution from ${res.current_phase}.` });
      await loadData(true);
    } catch (err: any) {
      setBanner({ type: "error", text: `Resume failed: ${err.message}` });
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
      setBanner({ type: "error", text: "Emergency stop triggered — active workflow aborted." });
      await loadData(true);
    } catch (err: any) {
      setBanner({ type: "error", text: `Stop failed: ${err.message}` });
    } finally {
      setActionLoading(false);
    }
  };

  const handleApprovalDecision = async (approvalId: string, decision: "APPROVE" | "REJECT") => {
    if (!currentProject) return;
    const trimmed = justificationText.trim();
    if (trimmed.length < 5) {
      setBanner({
        type: "error",
        text: "Please enter an operator audit justification (minimum 5 characters) before approving or rejecting.",
      });
      return;
    }
    setActionLoading(true);
    try {
      await api.decideApproval(
        currentProject.id,
        approvalId,
        decision,
        trimmed
      );
      setJustificationText("");
      setBanner({
        type: decision === "APPROVE" ? "success" : "info",
        text: decision === "APPROVE"
          ? "Approval granted — resuming multi-agent workflow execution."
          : "Action rejected — workflow continuing safely without active probe.",
      });
      await loadData(false);
    } catch (err: any) {
      setBanner({ type: "error", text: `Approval decision failed: ${err.message}` });
    } finally {
      setActionLoading(false);
    }
  };

  const agentsList = useMemo(() => {
    if (workflow?.active_agents && workflow.active_agents.length > 0) {
      return workflow.active_agents;
    }
    return STANDBY_AGENTS;
  }, [workflow]);

  const telemetryTotals = useMemo(() => {
    let promptTokens = 0;
    let completionTokens = 0;
    let totalCostUsd = 0;
    let completedCount = 0;
    let totalDecisions = 0;
    let totalToolCalls = 0;
    for (const a of agentsList) {
      promptTokens += Number(a.prompt_tokens || 0);
      completionTokens += Number(a.completion_tokens || 0);
      totalCostUsd += Number(a.total_cost_usd || 0);
      totalDecisions += Number(a.decisions_count || 0);
      totalToolCalls += Number(a.tool_calls_count || 0);
      if (a.status === "COMPLETED") completedCount += 1;
    }
    return {
      promptTokens,
      completionTokens,
      totalTokens: promptTokens + completionTokens,
      totalCostUsd,
      completedCount,
      totalDecisions,
      totalToolCalls,
    };
  }, [agentsList]);

  const activeScanProfile = (workflow?.state_data?.scan_profile || scanProfile || "QUICK").toUpperCase();
  const pendingApprovals = approvals.filter((a) => a.status === "PENDING");

  if (!currentProject) {
    return (
      <div className="p-8 text-center text-xs font-mono text-slate-500">
        Please select a project to view autonomous multi-agent orchestrator.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Bot className="h-5 w-5 text-cyan-400" />
            Autonomous Multi-Agent DAG Orchestrator
          </h1>
          <p className="text-xs text-slate-400">
            Hierarchical supervision across 7 specialized agents with live token accounting, tool telemetry, and thought trace auditing.
          </p>
        </div>

        {/* Workflow Actions & Scan Profile */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Scan Profile Selector */}
          <div className="flex items-center rounded border border-slate-700 bg-slate-900 p-0.5 text-xs font-mono">
            <button
              onClick={() => setScanProfile("QUICK")}
              disabled={actionLoading || ["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow?.status)}
              className={`px-2.5 py-1 rounded transition-colors disabled:opacity-60 ${
                scanProfile === "QUICK"
                  ? "bg-cyan-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Quick Scan: Live LiteLLM reasoning + lightweight WSTG smoke checks (~10-20s)"
            >
              ⚡ Quick Scan
            </button>
            <button
              onClick={() => setScanProfile("FULL")}
              disabled={actionLoading || ["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow?.status)}
              className={`px-2.5 py-1 rounded transition-colors disabled:opacity-60 ${
                scanProfile === "FULL"
                  ? "bg-cyan-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Full Scan: Live LLM reasoning + standard WSTG & header audit (~15-30s)"
            >
              🛡️ Full Scan
            </button>
            <button
              onClick={() => setScanProfile("DEEP")}
              disabled={actionLoading || ["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow?.status)}
              className={`px-2.5 py-1 rounded transition-colors disabled:opacity-60 ${
                scanProfile === "DEEP"
                  ? "bg-cyan-600 text-white font-bold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
              title="Deep Scan: Live LLM + Nuclei/Ffuf + active SQLi/XSS/Debug probes (~30-60s)"
            >
              🔬 Deep Scan
            </button>
          </div>

          {/* HITL Approval Gate Toggle */}
          <label
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-slate-800 bg-slate-900/70 text-[11px] font-mono text-slate-300 cursor-pointer select-none"
            title="When unchecked on Full/Deep scans, the agent pauses at an Approval Gate before active scanning"
          >
            <input
              type="checkbox"
              checked={autoApproveMedium}
              onChange={(e) => setAutoApproveMedium(e.target.checked)}
              className="accent-cyan-500 rounded"
            />
            Auto-Approve Medium
          </label>

          {workflow?.status === "RUNNING" ? (
            <>
              <button
                onClick={handlePause}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Pause className="h-3.5 w-3.5" /> Pause
              </button>
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Square className="h-3.5 w-3.5" /> Stop
              </button>
            </>
          ) : workflow?.status === "PAUSED" ? (
            <>
              <button
                onClick={handleResume}
                disabled={actionLoading}
                className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 fill-current" /> Resume DAG
              </button>
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Square className="h-3.5 w-3.5" /> Stop
              </button>
            </>
          ) : workflow?.status === "WAITING_APPROVAL" ? (
            <button
              onClick={handleStop}
              disabled={actionLoading}
              className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <Square className="h-3.5 w-3.5" /> Abort Gate
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={actionLoading}
              className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-lg shadow-red-950/40 disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              {actionLoading ? "Launching..." : `Start ${scanProfile} Scan`}
            </button>
          )}

          {workflow?.status &&
            ["FAILED", "STOPPED", "INTERRUPTED", "RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow.status) && (
              <button
                onClick={handleReset}
                disabled={actionLoading}
                title="Reset workflow to clean state"
                className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 rounded text-xs font-mono flex items-center gap-1 transition-colors disabled:opacity-50"
              >
                <RotateCcw className="h-3 w-3" /> Reset
              </button>
            )}

          <button
            onClick={() => loadData(false)}
            title="Refresh Swarm Status"
            className="p-1.5 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>

      {/* Operator Action / Workflow Error Banner */}
      {(banner || (workflow?.status === "FAILED" && workflow?.state_data?.error)) && (
        <div
          className={`p-3 rounded-lg border text-xs font-mono flex items-center justify-between gap-3 ${
            banner?.type === "error" || (workflow?.status === "FAILED" && workflow?.state_data?.error && !banner)
              ? "bg-red-950/60 border-red-800 text-red-300"
              : banner?.type === "success"
              ? "bg-emerald-950/60 border-emerald-800 text-emerald-300"
              : "bg-cyan-950/50 border-cyan-800 text-cyan-200"
          }`}
        >
          <span className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {banner?.text || `Workflow failed: ${workflow?.state_data?.error}`}
          </span>
          {banner && (
            <button onClick={() => setBanner(null)} className="text-slate-400 hover:text-slate-200">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      {/* Telemetry Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-surface-base border border-slate-800 rounded-lg p-3.5">
          <div className="text-[10px] font-mono uppercase text-slate-400">Active Profile & State</div>
          <div className="mt-1.5 flex items-center justify-between">
            <span className="text-sm font-bold font-mono text-cyan-400">{activeScanProfile}</span>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                workflow?.status === "COMPLETED"
                  ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                  : workflow?.status === "RUNNING"
                  ? "bg-cyan-950 text-cyan-300 border-cyan-700 animate-pulse"
                  : workflow?.status === "PAUSED" || workflow?.status === "WAITING_APPROVAL"
                  ? "bg-amber-950 text-amber-300 border-amber-700"
                  : workflow?.status === "FAILED" || workflow?.status === "STOPPED"
                  ? "bg-red-950 text-red-400 border-red-800"
                  : "bg-slate-800 text-slate-300 border-slate-700"
              }`}
            >
              {workflow?.status || "STANDBY"}
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-1">
            Engine: Live LiteLLM Gateway
          </div>
        </div>

        <div className="bg-surface-base border border-slate-800 rounded-lg p-3.5">
          <div className="text-[10px] font-mono uppercase text-slate-400 flex items-center gap-1">
            <Coins className="h-3 w-3 text-amber-400" /> Token Burn (In / Out)
          </div>
          <div className="mt-1.5 text-lg font-bold font-mono text-slate-100">
            {telemetryTotals.totalTokens.toLocaleString()}
          </div>
          <div className="text-[10px] font-mono text-slate-400 mt-0.5">
            {telemetryTotals.promptTokens.toLocaleString()} in / {telemetryTotals.completionTokens.toLocaleString()} out
          </div>
        </div>

        <div className="bg-surface-base border border-slate-800 rounded-lg p-3.5">
          <div className="text-[10px] font-mono uppercase text-slate-400">Estimated LLM Cost</div>
          <div className="mt-1.5 text-lg font-bold font-mono text-emerald-400">
            ${telemetryTotals.totalCostUsd.toFixed(4)}
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">
            {telemetryTotals.totalDecisions} traces • {telemetryTotals.totalToolCalls} tool calls
          </div>
        </div>

        <div className="bg-surface-base border border-slate-800 rounded-lg p-3.5">
          <div className="text-[10px] font-mono uppercase text-slate-400">Pipeline Progress</div>
          <div className="mt-1.5 text-lg font-bold font-mono text-slate-100">
            {telemetryTotals.completedCount} / {agentsList.length} Agents
          </div>
          <div className="text-[10px] font-mono text-slate-400 mt-0.5">
            Candidates: {workflow?.state_data?.candidate_findings_count ?? 0} • Confirmed: {workflow?.state_data?.confirmed_findings_count ?? 0}
          </div>
        </div>
      </div>

      {/* Workflow Phase Pipeline */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <span className="text-slate-400">
            Current Phase:{" "}
            <strong className={workflow?.status === "COMPLETED" ? "text-emerald-400" : "text-cyan-400"}>
              {workflow?.current_phase || "IDLE / READY"}
            </strong>
          </span>
          <span className="text-slate-400">
            Endpoints Mapped: <strong className="text-slate-200">{workflow?.state_data?.endpoints_count ?? 0}</strong>
          </span>
        </div>

        {/* 6-Step Phase Pipeline Breadcrumbs */}
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-center text-[11px] font-mono">
          {WORKFLOW_PHASES.map((phase, idx) => {
            const currentIdx = WORKFLOW_PHASES.indexOf(workflow?.current_phase);
            const isAllCompleted = workflow?.status === "COMPLETED" || workflow?.current_phase === "COMPLETED";
            const isCompletedStep = isAllCompleted || (currentIdx > idx && workflow?.status !== "STANDBY");
            const isCurrentStep = !isAllCompleted && workflow?.current_phase === phase;

            return (
              <div
                key={phase}
                className={`p-2 rounded border transition-all ${
                  isCompletedStep
                    ? "bg-emerald-950/50 border-emerald-700/80 text-emerald-300"
                    : isCurrentStep
                    ? "bg-cyan-950/80 border-cyan-500 text-cyan-300 font-bold shadow-lg shadow-cyan-950/50"
                    : "bg-slate-900/60 border-slate-800 text-slate-500"
                }`}
              >
                <div className="text-[10px] flex items-center justify-center gap-1 opacity-80">
                  {isCompletedStep ? (
                    <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                  ) : isCurrentStep ? (
                    <Clock className={`h-3 w-3 text-cyan-400 ${workflow?.status === "RUNNING" ? "animate-spin" : ""}`} />
                  ) : null}
                  Step {idx + 1}
                </div>
                <div className="truncate mt-0.5">{phase}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Human-in-the-Loop Approval Gate Panel */}
      {approvals.length > 0 && (
        <div
          className={`bg-surface-base border rounded-lg p-4 space-y-3 ${
            pendingApprovals.length > 0 ? "border-amber-600/80 bg-amber-950/10" : "border-slate-800"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className={`h-4 w-4 ${pendingApprovals.length > 0 ? "text-amber-400 animate-pulse" : "text-slate-400"}`} />
              <h3 className="text-sm font-semibold text-slate-200">
                Human-in-the-Loop Approval Gates ({pendingApprovals.length} Pending)
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-400">RoE Medium/High-Risk Action Authorization</span>
          </div>

          {pendingApprovals.length > 0 && (
            <div className="space-y-1">
              <label className="text-[10px] font-mono text-slate-400 uppercase">Operator Audit Justification</label>
              <input
                type="text"
                value={justificationText}
                onChange={(e) => setJustificationText(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-amber-500"
                placeholder="Enter justification (min 5 characters)..."
              />
            </div>
          )}

          <div className="space-y-2 max-h-60 overflow-y-auto">
            {approvals.map((req) => (
              <div
                key={req.id}
                className="p-3 bg-slate-900/80 border border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-cyan-400">
                      {req.agent_id}
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-300 border border-amber-800">
                      {req.risk_level}
                    </span>
                    <span className="font-sans font-semibold text-slate-100">{req.action}</span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Target: <span className="text-slate-300">{req.target}</span>
                  </div>
                  {req.justification && (
                    <div className="text-[10px] text-slate-500">Decision note: {req.justification}</div>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {req.status === "PENDING" ? (
                    <>
                      <button
                        onClick={() => handleApprovalDecision(req.id, "APPROVE")}
                        disabled={actionLoading}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-semibold flex items-center gap-1 disabled:opacity-50"
                      >
                        <Check className="h-3.5 w-3.5" /> Approve &amp; Resume
                      </button>
                      <button
                        onClick={() => handleApprovalDecision(req.id, "REJECT")}
                        disabled={actionLoading}
                        className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-xs font-semibold flex items-center gap-1 disabled:opacity-50"
                      >
                        <X className="h-3.5 w-3.5" /> Reject
                      </button>
                    </>
                  ) : (
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        req.status === "APPROVED"
                          ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                          : "bg-red-950 text-red-400 border-red-800"
                      }`}
                    >
                      {req.status}
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Agents Telemetry Table */}
      <div className="bg-surface-base border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-xs font-bold font-mono uppercase text-slate-300 flex items-center gap-2">
            <Cpu className="h-4 w-4 text-cyan-400" />
            Specialized Security Agents ({agentsList.length})
          </h3>
          <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500">
            {selectedAgentFilter && (
              <button
                onClick={() => setSelectedAgentFilter(null)}
                className="px-2 py-0.5 bg-cyan-950 border border-cyan-800 text-cyan-300 rounded hover:bg-cyan-900"
              >
                Filtering: {selectedAgentFilter} &times;
              </button>
            )}
            <span>Click an agent row to filter trace logs</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Agent</th>
                <th className="py-2.5 px-3">Operational Phase</th>
                <th className="py-2.5 px-3">State</th>
                <th className="py-2.5 px-3">Tokens (In / Out)</th>
                <th className="py-2.5 px-3">Cost ($)</th>
                <th className="py-2.5 px-3">Decisions</th>
                <th className="py-2.5 px-3">Tools Dispatched</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {agentsList.map((a: any) => {
                const isSelected = selectedAgentFilter === a.agent_id;
                return (
                  <tr
                    key={a.agent_id || a.agent_name}
                    onClick={() =>
                      setSelectedAgentFilter((prev) => (prev === a.agent_id ? null : a.agent_id))
                    }
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-cyan-950/30" : "hover:bg-slate-800/30"
                    }`}
                  >
                    <td className="py-2.5 px-3 text-slate-100 font-bold font-sans">
                      <div className="flex items-center gap-2">
                        <Bot className={`h-3.5 w-3.5 shrink-0 ${a.status === "RUNNING" ? "text-cyan-300 animate-bounce" : "text-cyan-400"}`} />
                        <span>{a.agent_name}</span>
                        <span className="text-[10px] font-mono text-slate-500">({a.agent_id})</span>
                      </div>
                      {a.error_message && (
                        <div className="text-[10px] font-mono font-normal text-red-400 mt-1">
                          Error: {a.error_message}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 text-[11px]">{a.phase}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          a.status === "COMPLETED"
                            ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                            : a.status === "RUNNING"
                            ? "bg-cyan-950 text-cyan-300 border-cyan-700 animate-pulse"
                            : a.status === "QUEUED"
                            ? "bg-slate-900 text-slate-400 border-slate-700"
                            : a.status === "WAITING_APPROVAL"
                            ? "bg-amber-950 text-amber-300 border-amber-700"
                            : a.status === "FAILED" || a.status === "STOPPED"
                            ? "bg-red-950 text-red-400 border-red-800"
                            : "bg-slate-800 text-slate-300 border-slate-700"
                        }`}
                      >
                        {a.status || "STANDBY"}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 text-[11px]">
                      {(a.prompt_tokens || 0).toLocaleString()} / {(a.completion_tokens || 0).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-emerald-400 text-[11px]">
                      ${Number(a.total_cost_usd || 0).toFixed(4)}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-400 font-bold">{a.decisions_count || 0}</td>
                    <td className="py-2.5 px-3 text-slate-300">{a.tool_calls_count || 0}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Agent Thought Trace & Tool Execution Tabs */}
      <div className="bg-surface-base border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab("decisions")}
              className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                activeTab === "decisions"
                  ? "bg-slate-800 text-purple-300 border border-slate-700"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <BrainCircuit className="h-4 w-4 text-purple-400" />
              Real-Time Agent Thought Trace &amp; Decisions ({decisions.length})
            </button>
            <button
              onClick={() => setActiveTab("tools")}
              className={`px-3 py-1.5 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                activeTab === "tools"
                  ? "bg-slate-800 text-cyan-300 border border-slate-700"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <Wrench className="h-4 w-4 text-cyan-400" />
              Tool Executions Dispatched ({toolCalls.length})
            </button>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            {selectedAgentFilter ? `Filtered: ${selectedAgentFilter}` : "Autonomous Reasoning Audit Log"}
          </span>
        </div>

        {initialLoading ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            Loading agent telemetry stream...
          </div>
        ) : activeTab === "decisions" ? (
          decisions.length === 0 ? (
            <div className="p-8 text-center text-xs font-mono text-slate-500 border border-slate-800/80 rounded bg-slate-900/40">
              No agent decisions recorded yet. Start the autonomous workflow to stream thought traces.
            </div>
          ) : (
            <div className="space-y-2.5 max-h-[30rem] overflow-y-auto pr-1">
              {decisions.map((d) => {
                const trace = formatTraceContent(d.thought_trace);
                return (
                  <div
                    key={d.id}
                    className="p-3 bg-slate-900/80 border border-slate-800 rounded-md space-y-2 font-mono text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-bold text-[10px]">
                          {d.agent_id || "AGT"}
                        </span>
                        <span className="text-cyan-400 font-bold font-sans">
                          {d.agent_name || "Specialized Agent"}
                        </span>
                        {d.phase && (
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                            {d.phase}
                          </span>
                        )}
                      </div>
                      <span className="text-slate-500">{new Date(d.created_at).toLocaleString()}</span>
                    </div>

                    {trace.isJson ? (
                      <pre className="p-2.5 bg-slate-950/90 border border-slate-800/80 rounded text-[11px] text-slate-200 overflow-x-auto whitespace-pre-wrap">
                        {trace.formatted}
                      </pre>
                    ) : (
                      <div className="text-slate-200 font-sans text-xs whitespace-pre-wrap">{trace.formatted}</div>
                    )}

                    <div className="flex flex-wrap items-center gap-4 text-[11px] pt-1.5 text-slate-400 border-t border-slate-800/60">
                      <span>Intent: <strong className="text-slate-300">{d.intent}</strong></span>
                      <span>Confidence: <strong className="text-emerald-400">{d.confidence || "High"}</strong></span>
                    </div>
                  </div>
                );
              })}
            </div>
          )
        ) : toolCalls.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500 border border-slate-800/80 rounded bg-slate-900/40">
            No structured tool calls recorded yet.
          </div>
        ) : (
          <div className="space-y-2.5 max-h-[30rem] overflow-y-auto pr-1">
            {toolCalls.map((tc) => (
              <div
                key={tc.id}
                className="p-3 bg-slate-900/80 border border-slate-800 rounded-md space-y-2 font-mono text-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold">
                      {tc.tool_name}
                    </span>
                    <span className="text-slate-300 font-sans">
                      by {tc.agent_name || tc.agent_id}
                    </span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                        tc.status === "SUCCESS"
                          ? "bg-emerald-950 text-emerald-400 border-emerald-800"
                          : "bg-red-950 text-red-400 border-red-800"
                      }`}
                    >
                      {tc.status}
                    </span>
                    {tc.duration_ms != null && (
                      <span className="text-slate-500 text-[10px]">{tc.duration_ms}ms</span>
                    )}
                  </div>
                  <span className="text-slate-500">{new Date(tc.created_at).toLocaleString()}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2 bg-slate-950/90 border border-slate-800/80 rounded overflow-x-auto">
                    <div className="text-[10px] text-slate-500 uppercase mb-1">Input Arguments</div>
                    <pre className="text-slate-300 whitespace-pre-wrap">{JSON.stringify(tc.input_arguments, null, 2)}</pre>
                  </div>
                  <div className="p-2 bg-slate-950/90 border border-slate-800/80 rounded overflow-x-auto">
                    <div className="text-[10px] text-slate-500 uppercase mb-1">Output Result</div>
                    <pre className="text-emerald-300 whitespace-pre-wrap">{JSON.stringify(tc.output_result || {}, null, 2)}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
