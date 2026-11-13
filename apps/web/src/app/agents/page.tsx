"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  Bot,
  Play,
  Pause,
  Square,
  Cpu,
  RefreshCw,
  Coins,
  ShieldAlert,
  AlertCircle,
  RotateCcw,
  CheckCircle2,
  Clock,
  X,
  Radio,
  ArrowRight,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { useToast } from "@/lib/ToastContext";
import { api } from "@/lib/api";
import { EngagementStepper } from "@/components/EngagementStepper";
import { StepFooterNav } from "@/components/StepFooterNav";
import { EngagementStepGuard } from "@/components/EngagementStepGuard";
import { AgentTerminal, DecisionLog, ToolCallLog, ApprovalGate } from "@/components/AgentTerminal";

const WORKFLOW_PHASES = [
  "PLANNING",
  "RECON",
  "WSTG_PLANNING",
  "ACTIVE_ASSESSMENT",
  "VALIDATION",
  "REPORTING",
] as const;

const STANDBY_AGENTS = [
  { agent_id: "AGT-01", agent_name: "Project Planning Agent", phase: "PLANNING", role: "Orchestration & RoE Validation", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-03", agent_name: "Reconnaissance & Surface Mapping Agent", phase: "RECON", role: "Endpoint & Subdomain Crawler", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-05", agent_name: "WSTG Assessment Agent", phase: "WSTG_PLANNING", role: "106-Test Matrix Generation", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-09", agent_name: "Vulnerability Detection Agent", phase: "ACTIVE_ASSESSMENT", role: "SQLi, XSS & Input Prober", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-07", agent_name: "Authorization Testing Agent", phase: "ACTIVE_ASSESSMENT", role: "IDOR & Privilege Escalation", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-11", agent_name: "Vulnerability Validation & QC Agent", phase: "VALIDATION", role: "False Positive Proof Filter", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
  { agent_id: "AGT-15", agent_name: "PTES Reporting Agent", phase: "REPORTING", role: "Technical & Executive Deliverable", status: "STANDBY", prompt_tokens: 0, completion_tokens: 0, total_cost_usd: 0, decisions_count: 0, tool_calls_count: 0 },
];

export default function AgentsPage() {
  return (
    <EngagementStepGuard requiredStep={4} stepTitle="Multi-Agent Execution DAG">
      <AgentsContent />
    </EngagementStepGuard>
  );
}

function AgentsContent() {
  const { currentProject, refreshProjects } = useProject();
  const { confirmDialog } = useToast();
  const [workflow, setWorkflow] = useState<any>(null);
  const [decisions, setDecisions] = useState<DecisionLog[]>([]);
  const [toolCalls, setToolCalls] = useState<ToolCallLog[]>([]);
  const [approvals, setApprovals] = useState<ApprovalGate[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [scanProfile, setScanProfile] = useState<"QUICK" | "FULL" | "DEEP">("QUICK");
  const [autoApproveMedium, setAutoApproveMedium] = useState<boolean>(true);
  const [selectedAgentFilter, setSelectedAgentFilter] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ type: "info" | "success" | "error"; text: string } | null>(null);
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
      loadData(true);
      if (status === "COMPLETED") {
        setBanner({
          type: "success",
          text: `${workflow?.state_data?.scan_profile || scanProfile} workflow completed successfully — all agent telemetry and findings recorded.`,
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
        text: "Workflow paused at Human-in-the-Loop Approval Gate — operator authorization required.",
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
      if (currentProject.status !== "ACTIVE" && currentProject.status !== "COMPLETED") {
        try {
          await api.updateProject(currentProject.id, { status: "ACTIVE" });
          await refreshProjects();
        } catch (e) {
          console.warn("Could not transition project status to ACTIVE", e);
        }
      }
      const res = await api.startWorkflow(currentProject.id, autoApproveMedium, scanProfile, true);
      setWorkflow(res);
      setBanner({
        type: "info",
        text: `Launched ${scanProfile} multi-agent DAG swarm — streaming live telemetry below.`,
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
      setBanner({ type: "info", text: "Workflow state reset cleanly. Ready for new launch." });
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
      setBanner({ type: "info", text: `Workflow paused at phase ${res.current_phase}. Click Resume to proceed.` });
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
      setBanner({ type: "info", text: `Resumed workflow execution from phase ${res.current_phase}.` });
      await loadData(true);
    } catch (err: any) {
      setBanner({ type: "error", text: `Resume failed: ${err.message}` });
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    if (!currentProject) return;
    const ok = await confirmDialog({
      title: "Emergency Abort Autonomous Pentest",
      message: "Are you sure you want to emergency abort the active autonomous pentest? All active agent child processes and sandbox tool executions will be immediately halted.",
      confirmText: "Abort Assessment",
      isDestructive: true,
    });
    if (!ok) return;
    setActionLoading(true);
    try {
      const res = await api.stopWorkflow(currentProject.id);
      setWorkflow(res);
      setBanner({ type: "error", text: "Emergency stop triggered — active agents halted." });
      await loadData(true);
    } catch (err: any) {
      setBanner({ type: "error", text: `Stop failed: ${err.message}` });
    } finally {
      setActionLoading(false);
    }
  };

  const handleApprovalDecision = async (approvalId: string, decision: "APPROVE" | "REJECT", justification: string) => {
    if (!currentProject) return;
    setActionLoading(true);
    try {
      await api.decideApproval(currentProject.id, approvalId, decision, justification);
      setBanner({
        type: decision === "APPROVE" ? "success" : "info",
        text: decision === "APPROVE"
          ? "Approval granted — resumed multi-agent workflow execution."
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

  if (!currentProject) {
    return (
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-xs">
          <Bot className="w-10 h-10 text-slate-300 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-800">No Engagement Selected</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            Please select an active penetration testing engagement from the Engagements directory to view the multi-agent DAG orchestrator.
          </p>
          <div className="mt-4">
            <Link
              href="/projects"
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-blue-900 hover:bg-blue-800 text-xs font-semibold text-white shadow-xs transition-colors"
            >
              <span>Select Engagement</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 6-Phase Engagement Lifecycle Stepper */}
      <EngagementStepper />

      {/* Header & Controls Toolbar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 sm:p-5 shadow-xs flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-700">
              <Bot className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-900 flex items-center gap-2">
                Autonomous Multi-Agent DAG Orchestrator
                <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                  Phase 4 of 6
                </span>
              </h1>
              <p className="text-xs text-slate-500 mt-0.5">
                Hierarchical LangGraph supervision across 7 specialized offensive agents with live token accounting and transparent reasoning traces.
              </p>
            </div>
          </div>
        </div>

        {/* Scan Profiles & Execution Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {/* Profile Switcher */}
          <div className="flex items-center rounded-lg border border-slate-200 bg-slate-50 p-1 text-xs font-medium">
            <button
              onClick={() => setScanProfile("QUICK")}
              disabled={actionLoading || ["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow?.status)}
              className={`px-3 py-1.5 rounded-md transition-all disabled:opacity-60 text-xs ${
                scanProfile === "QUICK"
                  ? "bg-white text-blue-900 font-bold shadow-xs border border-slate-200/80"
                  : "text-slate-600 hover:text-slate-900"
              }`}
              title="Quick Scan: Live LiteLLM reasoning + lightweight WSTG smoke checks (~10-20s)"
            >
              ⚡ Quick
            </button>
            <button
              onClick={() => setScanProfile("FULL")}
              disabled={actionLoading || ["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow?.status)}
              className={`px-3 py-1.5 rounded-md transition-all disabled:opacity-60 text-xs ${
                scanProfile === "FULL"
                  ? "bg-white text-blue-900 font-bold shadow-xs border border-slate-200/80"
                  : "text-slate-600 hover:text-slate-900"
              }`}
              title="Full Scan: Standard WSTG matrix + header audit + passive surface inspection (~15-30s)"
            >
              🛡️ Full
            </button>
            <button
              onClick={() => setScanProfile("DEEP")}
              disabled={actionLoading || ["RUNNING", "PAUSED", "WAITING_APPROVAL"].includes(workflow?.status)}
              className={`px-3 py-1.5 rounded-md transition-all disabled:opacity-60 text-xs ${
                scanProfile === "DEEP"
                  ? "bg-white text-blue-900 font-bold shadow-xs border border-slate-200/80"
                  : "text-slate-600 hover:text-slate-900"
              }`}
              title="Deep Scan: Full active SQLi/XSS/Debug probes + Nuclei fuzzing (~30-60s)"
            >
              🔬 Deep
            </button>
          </div>

          {/* HITL Auto-Approve Checkbox */}
          <label
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-200 bg-slate-50/80 text-[11px] font-sans text-slate-700 cursor-pointer select-none hover:bg-slate-100/80 transition-colors"
            title="When unchecked on Full/Deep scans, the agent pauses at an Approval Gate before medium-risk probes"
          >
            <input
              type="checkbox"
              checked={autoApproveMedium}
              onChange={(e) => setAutoApproveMedium(e.target.checked)}
              className="accent-blue-600 rounded"
            />
            Auto-Approve Medium
          </label>

          {/* Action Trigger Buttons */}
          {workflow?.status === "RUNNING" ? (
            <>
              <button
                onClick={handlePause}
                disabled={actionLoading}
                className="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50"
              >
                <Pause className="h-3.5 w-3.5" /> Pause
              </button>
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50"
              >
                <Square className="h-3.5 w-3.5" /> Stop
              </button>
            </>
          ) : workflow?.status === "PAUSED" ? (
            <>
              <button
                onClick={handleResume}
                disabled={actionLoading}
                className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5 fill-current" /> Resume DAG
              </button>
              <button
                onClick={handleStop}
                disabled={actionLoading}
                className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50"
              >
                <Square className="h-3.5 w-3.5" /> Abort
              </button>
            </>
          ) : workflow?.status === "WAITING_APPROVAL" ? (
            <button
              onClick={handleStop}
              disabled={actionLoading}
              className="px-3.5 py-1.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-xs transition-colors disabled:opacity-50"
            >
              <Square className="h-3.5 w-3.5" /> Abort Gate
            </button>
          ) : (
            <button
              onClick={handleStart}
              disabled={actionLoading}
              className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-xs hover:shadow disabled:opacity-50 cursor-pointer"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              {actionLoading ? "Launching..." : `Start ${scanProfile} Scan`}
            </button>
          )}

          {workflow?.status &&
            ["FAILED", "STOPPED", "INTERRUPTED", "RUNNING", "PAUSED", "WAITING_APPROVAL", "COMPLETED"].includes(workflow.status) && (
              <button
                onClick={handleReset}
                disabled={actionLoading}
                title="Reset workflow to standby state"
                className="px-2.5 py-1.5 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-lg text-xs font-medium flex items-center gap-1 transition-colors disabled:opacity-50 shadow-xs cursor-pointer"
              >
                <RotateCcw className="h-3 w-3 text-slate-500" /> Reset
              </button>
            )}

          <button
            onClick={() => loadData(false)}
            title="Refresh Swarm Status"
            className="p-2 bg-white border border-slate-200 hover:bg-slate-50 rounded-lg text-slate-600 transition-colors shadow-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-blue-600" : ""}`} />
          </button>
        </div>
      </div>

      {/* Operator Notification Banner */}
      {(banner || (workflow?.status === "FAILED" && workflow?.state_data?.error)) && (
        <div
          className={`p-3.5 rounded-xl border text-xs font-sans flex items-center justify-between gap-3 shadow-xs ${
            banner?.type === "error" || (workflow?.status === "FAILED" && workflow?.state_data?.error && !banner)
              ? "bg-rose-50 border-rose-200 text-rose-900"
              : banner?.type === "success"
              ? "bg-emerald-50 border-emerald-200 text-emerald-900"
              : "bg-blue-50 border-blue-200 text-blue-900"
          }`}
        >
          <span className="flex items-center gap-2 font-medium">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {banner?.text || `Workflow failed: ${workflow?.state_data?.error}`}
          </span>
          {banner && (
            <button onClick={() => setBanner(null)} className="text-slate-400 hover:text-slate-700">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      {/* Telemetry KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Active Profile &amp; State
          </div>
          <div className="mt-2 flex items-center justify-between">
            <span className="text-base font-bold font-mono text-blue-900">{activeScanProfile}</span>
            <span
              className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                workflow?.status === "COMPLETED"
                  ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                  : workflow?.status === "RUNNING"
                  ? "bg-blue-50 text-blue-700 border-blue-200 animate-pulse"
                  : workflow?.status === "PAUSED" || workflow?.status === "WAITING_APPROVAL"
                  ? "bg-amber-50 text-amber-700 border-amber-200"
                  : workflow?.status === "FAILED" || workflow?.status === "STOPPED"
                  ? "bg-rose-50 text-rose-700 border-rose-200"
                  : "bg-slate-100 text-slate-600 border-slate-200"
              }`}
            >
              {workflow?.status || "STANDBY"}
            </span>
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">
            Engine: Live LiteLLM Gateway
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-1">
            <Coins className="h-3.5 w-3.5 text-amber-500" /> Token Burn (Total)
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-slate-900">
            {telemetryTotals.totalTokens.toLocaleString()}
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">
            {telemetryTotals.promptTokens.toLocaleString()} in / {telemetryTotals.completionTokens.toLocaleString()} out
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Estimated LLM Cost
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-emerald-700">
            ${telemetryTotals.totalCostUsd.toFixed(4)}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
            {telemetryTotals.totalDecisions} traces • {telemetryTotals.totalToolCalls} tool executions
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-xs">
          <div className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
            Swarm Agents Complete
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-slate-900">
            {telemetryTotals.completedCount} / {agentsList.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
            Findings: {workflow?.state_data?.confirmed_findings_count ?? 0} confirmed ({workflow?.state_data?.candidate_findings_count ?? 0} candidates)
          </div>
        </div>
      </div>

      {/* Workflow Phase Pipeline Bar */}
      <div className="bg-white border border-slate-200 rounded-xl p-4 sm:p-5 shadow-xs space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
          <span className="text-slate-600">
            Current Phase:{" "}
            <strong className={workflow?.status === "COMPLETED" ? "text-emerald-700 font-bold" : "text-blue-700 font-bold"}>
              {workflow?.current_phase || "IDLE / READY"}
            </strong>
          </span>
          <span className="text-slate-600">
            Endpoints Evaluated: <strong className="text-slate-900 font-bold">{workflow?.state_data?.endpoints_count ?? 0}</strong>
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-center text-xs font-mono">
          {WORKFLOW_PHASES.map((phase, idx) => {
            const currentIdx = WORKFLOW_PHASES.indexOf(workflow?.current_phase);
            const isAllCompleted = workflow?.status === "COMPLETED" || workflow?.current_phase === "COMPLETED";
            const isCompletedStep = isAllCompleted || (currentIdx > idx && workflow?.status !== "STANDBY");
            const isCurrentStep = !isAllCompleted && workflow?.current_phase === phase;

            return (
              <div
                key={phase}
                className={`p-2 rounded-lg border transition-all ${
                  isCompletedStep
                    ? "bg-emerald-50 border-emerald-200 text-emerald-900 font-medium"
                    : isCurrentStep
                    ? "bg-blue-50 border-blue-600 text-blue-900 font-bold ring-1 ring-blue-500/20 shadow-xs"
                    : "bg-slate-50 border-slate-200 text-slate-500"
                }`}
              >
                <div className="text-[10px] flex items-center justify-center gap-1 opacity-80">
                  {isCompletedStep ? (
                    <CheckCircle2 className="h-3 w-3 text-emerald-600" />
                  ) : isCurrentStep ? (
                    <Clock className={`h-3 w-3 text-blue-600 ${workflow?.status === "RUNNING" ? "animate-spin" : ""}`} />
                  ) : null}
                  Step {idx + 1}
                </div>
                <div className="truncate mt-0.5 text-[11px]">{phase}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* CLAUDE CODE LIVE AGENT STREAM TERMINAL */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-blue-600" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-700">
              Live Agent Streaming Console (Real-Time Forensic Feed)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            Interactive Agent Execution Viewport
          </span>
        </div>

        <AgentTerminal
          workflow={workflow}
          decisions={decisions}
          toolCalls={toolCalls}
          approvals={approvals}
          selectedAgentId={selectedAgentFilter}
          onApprovalDecision={handleApprovalDecision}
        />
      </div>

      {/* Specialized Security Agents Table */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="p-3.5 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2 bg-slate-50/60">
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-blue-600" />
            <h3 className="text-xs font-bold font-mono uppercase text-slate-700">
              Specialized Offensive Agents Telemetry ({agentsList.length})
            </h3>
          </div>
          <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500">
            {selectedAgentFilter && (
              <button
                onClick={() => setSelectedAgentFilter(null)}
                className="px-2 py-0.5 bg-blue-50 border border-blue-200 text-blue-800 rounded-md font-semibold hover:bg-blue-100"
              >
                Filtered: {selectedAgentFilter} &times;
              </button>
            )}
            <span>Click row to scope terminal logs</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 text-slate-600 text-[10px] uppercase border-b border-slate-200 font-semibold">
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
            <tbody className="divide-y divide-slate-100">
              {agentsList.map((a: any) => {
                const isSelected = selectedAgentFilter === a.agent_id;
                return (
                  <tr
                    key={a.agent_id || a.agent_name}
                    onClick={() =>
                      setSelectedAgentFilter((prev) => (prev === a.agent_id ? null : a.agent_id))
                    }
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-blue-50/70" : "hover:bg-slate-50/80"
                    }`}
                  >
                    <td className="py-3 px-3 text-slate-900 font-semibold font-sans">
                      <div className="flex items-center gap-2">
                        <Bot className={`h-4 w-4 shrink-0 ${a.status === "RUNNING" ? "text-blue-600 animate-pulse" : "text-slate-500"}`} />
                        <span>{a.agent_name}</span>
                        <span className="text-[10px] font-mono text-slate-500 font-normal">({a.agent_id})</span>
                      </div>
                      {a.error_message && (
                        <div className="text-[10px] font-mono font-normal text-rose-600 mt-1">
                          Error: {a.error_message}
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-3 text-slate-600 text-[11px]">{a.phase}</td>
                    <td className="py-3 px-3">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold border ${
                          a.status === "COMPLETED"
                            ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                            : a.status === "RUNNING"
                            ? "bg-blue-50 text-blue-700 border-blue-200"
                            : a.status === "QUEUED"
                            ? "bg-slate-100 text-slate-600 border-slate-200"
                            : a.status === "WAITING_APPROVAL"
                            ? "bg-amber-50 text-amber-700 border-amber-200"
                            : a.status === "FAILED" || a.status === "STOPPED"
                            ? "bg-rose-50 text-rose-700 border-rose-200"
                            : "bg-slate-100 text-slate-600 border-slate-200"
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            a.status === "COMPLETED"
                              ? "bg-emerald-600"
                              : a.status === "RUNNING"
                              ? "bg-blue-600 animate-pulse"
                              : a.status === "WAITING_APPROVAL"
                              ? "bg-amber-600 animate-pulse"
                              : a.status === "FAILED" || a.status === "STOPPED"
                              ? "bg-rose-600"
                              : "bg-slate-400"
                          }`}
                        />
                        {a.status || "STANDBY"}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-700 text-[11px]">
                      {(a.prompt_tokens || 0).toLocaleString()} / {(a.completion_tokens || 0).toLocaleString()}
                    </td>
                    <td className="py-3 px-3 text-emerald-700 font-semibold text-[11px]">
                      ${Number(a.total_cost_usd || 0).toFixed(4)}
                    </td>
                    <td className="py-3 px-3 text-blue-700 font-bold">{a.decisions_count || 0}</td>
                    <td className="py-3 px-3 text-slate-700">{a.tool_calls_count || 0}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* 6-Phase Linear Bottom Navigation */}
      <StepFooterNav
        currentStep={4}
        prevStepPath="/wstg"
        prevStepLabel="OWASP WSTG Plan"
        nextStepPath="/findings"
        nextStepLabel="Proceed to Findings & Retest Engine"
        canAdvance={true}
      />
    </div>
  );
}
