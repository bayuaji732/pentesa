"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  Copy,
  Check,
  ArrowDown,
  Maximize2,
  Minimize2,
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  X,
  Clock,
  Radio,
  Sliders,
  CheckCircle2,
  Trash2,
} from "lucide-react";

export interface DecisionLog {
  id: string;
  agent_execution_id?: string;
  agent_id?: string;
  agent_name?: string;
  phase?: string;
  thought_trace: string;
  intent?: string;
  context_summary?: string | null;
  confidence?: string | null;
  created_at: string;
}

export interface ToolCallLog {
  id: string;
  agent_execution_id?: string;
  agent_id?: string;
  agent_name?: string;
  phase?: string;
  tool_name: string;
  input_arguments: Record<string, any> | string;
  output_result?: Record<string, any> | string | null;
  status: string;
  duration_ms?: number | null;
  created_at: string;
}

export interface ApprovalGate {
  id: string;
  project_id?: string;
  workflow_execution_id?: string | null;
  agent_id: string;
  action: string;
  target: string;
  risk_level: string;
  parameters?: Record<string, any> | null;
  status: string;
  justification?: string | null;
  requested_at?: string;
  created_at?: string;
  decided_at?: string | null;
}

interface AgentTerminalProps {
  workflow: any;
  decisions: DecisionLog[];
  toolCalls: ToolCallLog[];
  approvals: ApprovalGate[];
  selectedAgentId?: string | null;
  onApprovalDecision?: (approvalId: string, decision: "APPROVE" | "REJECT", justification: string) => Promise<void>;
  onClearLogs?: () => void;
  className?: string;
}

type StreamEvent =
  | { id: string; type: "decision"; timestamp: string; data: DecisionLog }
  | { id: string; type: "tool"; timestamp: string; data: ToolCallLog }
  | { id: string; type: "approval"; timestamp: string; data: ApprovalGate };

function formatToolOutput(output: any): { lines: string[]; totalLines: number } {
  if (!output) return { lines: [], totalLines: 0 };
  let str = "";
  if (typeof output === "string") {
    str = output;
  } else {
    str = JSON.stringify(output, null, 2);
  }
  const lines = str.split("\n");
  return { lines, totalLines: lines.length };
}

function formatToolArgs(args: any): string {
  if (!args) return "";
  if (typeof args === "string") return args;
  try {
    if (args.command) return String(args.command);
    if (args.url) {
      const method = args.method || "GET";
      return `-X ${method} "${args.url}"`;
    }
    return Object.entries(args)
      .map(([k, v]) => `--${k} ${typeof v === "object" ? JSON.stringify(v) : v}`)
      .join(" ");
  } catch {
    return JSON.stringify(args);
  }
}

export function AgentTerminal({
  workflow,
  decisions = [],
  toolCalls = [],
  approvals = [],
  selectedAgentId = null,
  onApprovalDecision,
  onClearLogs,
  className = "",
}: AgentTerminalProps) {
  const [filterType, setFilterType] = useState<"all" | "thoughts" | "tools" | "approvals">("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const [isCopied, setIsCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [expandedOutputs, setExpandedOutputs] = useState<Record<string, boolean>>({});
  const [justifications, setJustifications] = useState<Record<string, string>>({});
  const [submittingGateId, setSubmittingGateId] = useState<string | null>(null);

  const scrollRef = useRef<HTMLDivElement>(null);

  // Chronologically unified linear stream
  const eventStream: StreamEvent[] = useMemo(() => {
    const events: StreamEvent[] = [];

    decisions.forEach((d) => {
      if (!selectedAgentId || d.agent_id === selectedAgentId) {
        events.push({
          id: `dec-${d.id}`,
          type: "decision",
          timestamp: d.created_at || new Date().toISOString(),
          data: d,
        });
      }
    });

    toolCalls.forEach((tc) => {
      if (!selectedAgentId || tc.agent_id === selectedAgentId) {
        events.push({
          id: `tool-${tc.id}`,
          type: "tool",
          timestamp: tc.created_at || new Date().toISOString(),
          data: tc,
        });
      }
    });

    approvals.forEach((app) => {
      if (!selectedAgentId || app.agent_id === selectedAgentId) {
        events.push({
          id: `app-${app.id}`,
          type: "approval",
          timestamp: app.requested_at || app.created_at || new Date().toISOString(),
          data: app,
        });
      }
    });

    return events.sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }, [decisions, toolCalls, approvals, selectedAgentId]);

  // Filtered stream
  const filteredEvents = useMemo(() => {
    if (filterType === "thoughts") return eventStream.filter((e) => e.type === "decision");
    if (filterType === "tools") return eventStream.filter((e) => e.type === "tool");
    if (filterType === "approvals") return eventStream.filter((e) => e.type === "approval");
    return eventStream;
  }, [eventStream, filterType]);

  // Auto-scroll inside the container only (never scrolling the parent window)
  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredEvents, autoScroll]);

  const toggleOutputExpand = (eventId: string) => {
    setExpandedOutputs((prev) => ({ ...prev, [eventId]: !prev[eventId] }));
  };

  const handleCopyLogs = () => {
    const textOutput = filteredEvents
      .map((ev) => {
        const time = new Date(ev.timestamp).toLocaleTimeString();
        if (ev.type === "decision") {
          return `[${time}] [THOUGHT] ${ev.data.agent_id} (${ev.data.agent_name || ""}): ${ev.data.thought_trace}`;
        }
        if (ev.type === "tool") {
          return `[${time}] [EXEC] $ ${ev.data.tool_name} ${formatToolArgs(ev.data.input_arguments)} -> ${ev.data.status} (${ev.data.duration_ms || 0}ms)`;
        }
        return `[${time}] [GATE] ${ev.data.risk_level} ${ev.data.action} on ${ev.data.target} -> ${ev.data.status}`;
      })
      .join("\n");

    navigator.clipboard.writeText(textOutput);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const handleGateAction = async (gateId: string, decision: "APPROVE" | "REJECT") => {
    if (!onApprovalDecision) return;
    const just = (justifications[gateId] || "").trim() || (decision === "APPROVE" ? "Approved by Operator" : "Rejected by Operator");
    setSubmittingGateId(gateId);
    try {
      await onApprovalDecision(gateId, decision, just);
      setJustifications((prev) => {
        const next = { ...prev };
        delete next[gateId];
        return next;
      });
    } finally {
      setSubmittingGateId(null);
    }
  };

  const isRunning = workflow?.status === "RUNNING";
  const isWaitingGate = workflow?.status === "WAITING_APPROVAL";
  const pendingApprovals = approvals.filter((a) => a.status === "PENDING");
  const currentPhase = workflow?.current_phase || "STANDBY";
  const scanProfile = (workflow?.state_data?.scan_profile || "QUICK").toUpperCase();

  return (
    <div
      className={`flex flex-col rounded-xl border border-slate-800 bg-[#080c14] text-slate-100 shadow-2xl overflow-hidden font-mono text-xs transition-all ${
        isExpanded ? "fixed inset-4 z-50 shadow-2xl" : "h-[38rem]"
      } ${className}`}
    >
      {/* 1. Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between px-3.5 py-2.5 bg-[#0f172a] border-b border-slate-800/90 gap-3 select-none">
        {/* Left: Stream Indicator & Title */}
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#ff5f56] inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#ffbd2e] inline-block" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#27c93f] inline-block" />
          </div>

          <div className="h-3.5 w-px bg-slate-800 hidden sm:block" />

          <div className="flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-[11px] font-semibold text-slate-200 tracking-wide">
              FORENSIC AGENT STREAM
            </span>
            <span className="text-[10px] text-slate-500 font-normal">
              [{currentPhase.toLowerCase()}]
            </span>
          </div>

          {selectedAgentId && (
            <span className="px-1.5 py-0.2 rounded bg-sky-950 border border-sky-800 text-sky-300 text-[10px] font-bold">
              filter:{selectedAgentId}
            </span>
          )}
        </div>

        {/* Center: System Telemetry */}
        <div className="hidden lg:flex items-center gap-4 text-[11px] text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">Router:</span>
            <span className="text-slate-300">LiteLLM Gateway</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">Profile:</span>
            <span className="text-sky-400 font-bold">{scanProfile}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-slate-500">State:</span>
            <span
              className={`flex items-center gap-1 font-bold ${
                isRunning
                  ? "text-emerald-400"
                  : isWaitingGate
                  ? "text-amber-400 animate-pulse"
                  : "text-slate-400"
              }`}
            >
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  isRunning
                    ? "bg-emerald-400 animate-ping"
                    : isWaitingGate
                    ? "bg-amber-400"
                    : "bg-slate-500"
                }`}
              />
              {workflow?.status || "STANDBY"}
            </span>
          </div>
        </div>

        {/* Right: Controls (Filters, Follow, Copy, Fullscreen) */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Filter Chips */}
          <div className="flex items-center bg-[#080c14] border border-slate-800 rounded p-0.5 text-[10px]">
            <button
              onClick={() => setFilterType("all")}
              className={`px-2 py-0.5 rounded transition-colors ${
                filterType === "all" ? "bg-slate-800 text-white font-bold" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              all ({eventStream.length})
            </button>
            <button
              onClick={() => setFilterType("thoughts")}
              className={`px-2 py-0.5 rounded transition-colors ${
                filterType === "thoughts" ? "bg-sky-950 text-sky-300 font-bold" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              thoughts
            </button>
            <button
              onClick={() => setFilterType("tools")}
              className={`px-2 py-0.5 rounded transition-colors ${
                filterType === "tools" ? "bg-purple-950 text-purple-300 font-bold" : "text-slate-400 hover:text-slate-200"
              }`}
            >
              tools
            </button>
            {pendingApprovals.length > 0 && (
              <button
                onClick={() => setFilterType("approvals")}
                className={`px-2 py-0.5 rounded transition-colors ${
                  filterType === "approvals" ? "bg-amber-950 text-amber-300 font-bold" : "text-amber-400 hover:text-amber-200"
                }`}
              >
                gates ({pendingApprovals.length})
              </button>
            )}
          </div>

          {/* Auto Scroll Toggle */}
          <button
            onClick={() => setAutoScroll((prev) => !prev)}
            title={autoScroll ? "Auto-scroll ON (click to pause)" : "Auto-scroll PAUSED (click to follow)"}
            className={`p-1.5 rounded border text-[10px] flex items-center gap-1 transition-colors ${
              autoScroll
                ? "bg-sky-950/60 border-sky-800 text-sky-300"
                : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
            }`}
          >
            <ArrowDown className={`w-3 h-3 ${autoScroll ? "animate-bounce" : ""}`} />
            <span className="hidden sm:inline">{autoScroll ? "Follow" : "Paused"}</span>
          </button>

          {/* Clear Console */}
          {onClearLogs && (
            <button
              onClick={onClearLogs}
              title="Clear visible terminal console"
              className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-rose-400 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}

          {/* Copy Logs */}
          <button
            onClick={handleCopyLogs}
            title="Copy forensic log stream"
            className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>

          {/* Fullscreen */}
          <button
            onClick={() => setIsExpanded((prev) => !prev)}
            title={isExpanded ? "Exit Fullscreen" : "Fullscreen"}
            className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* 2. Top-Down Forensic Event Stream (Starts at Line 1 at the very top) */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-4 py-3 space-y-2 font-mono text-[11.5px] leading-relaxed select-text bg-[#080c14]"
      >
        {/* Line 1: Natural initialization log (always starts at the top, never at the bottom!) */}
        <div className="flex items-start gap-2 text-slate-500 py-0.5 select-none border-b border-slate-900/60 pb-1.5">
          <span className="text-slate-600 text-[10px] shrink-0">00:00:00.000</span>
          <span className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-400 text-[10px] font-bold shrink-0">
            [SYS]
          </span>
          <span className="text-slate-400">
            Forensic agent event stream initialized · LiteLLM Router active · Layer 1 &amp; 2 RoE guard active.
          </span>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="flex items-start gap-2 text-slate-600 py-0.5 select-none">
            <span className="text-slate-600 text-[10px] shrink-0">00:00:00.010</span>
            <span className="px-1.5 py-0.2 rounded bg-slate-900 text-slate-500 text-[10px] font-bold shrink-0">
              [STANDBY]
            </span>
            <span className="text-slate-500">
              Awaiting scan launch. Click &quot;Start Scan&quot; in the toolbar above to begin autonomous assessment.
            </span>
          </div>
        ) : (
          filteredEvents.map((event) => {
            const timeStr = new Date(event.timestamp).toLocaleTimeString();

            // 1. REASONING TRACE / THOUGHT
            if (event.type === "decision") {
              const d = event.data;
              return (
                <div key={event.id} className="group transition-colors hover:bg-slate-900/40 px-1 py-1 rounded">
                  <div className="flex items-start gap-2">
                    <span className="text-slate-600 shrink-0 select-none text-[10px] mt-0.5">
                      {timeStr}
                    </span>
                    <span className="px-1.5 py-0.2 rounded bg-sky-950/80 border border-sky-800 text-sky-300 text-[10px] font-bold shrink-0 select-none">
                      [THOUGHT]
                    </span>
                    <div className="flex-1 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sky-300 font-semibold">
                          {d.agent_name || d.agent_id || "Orchestrator"}
                        </span>
                        {d.phase && (
                          <span className="text-slate-500 text-[10px]">
                            [{d.phase.toLowerCase()}]
                          </span>
                        )}
                        {d.intent && (
                          <span className="text-slate-400 text-[10px] italic">
                            — {d.intent}
                          </span>
                        )}
                        {d.confidence && (
                          <span className="text-emerald-500 text-[10px] ml-auto">
                            confidence: {d.confidence}
                          </span>
                        )}
                      </div>

                      <div className="text-slate-300 font-sans text-xs whitespace-pre-wrap pl-3 border-l-2 border-sky-900/60 leading-normal">
                        {d.thought_trace}
                      </div>
                    </div>
                  </div>
                </div>
              );
            }

            // 2. TOOL CALL & CLI EXECUTION
            if (event.type === "tool") {
              const tc = event.data;
              const isSuccess = tc.status === "SUCCESS";
              const formatted = formatToolOutput(tc.output_result);
              const isOutputExpanded = !!expandedOutputs[event.id];
              const previewLines = isOutputExpanded ? formatted.lines : formatted.lines.slice(0, 4);

              return (
                <div key={event.id} className="group transition-colors hover:bg-slate-900/40 px-1 py-1 rounded space-y-1">
                  <div className="flex items-start gap-2">
                    <span className="text-slate-600 shrink-0 select-none text-[10px] mt-0.5">
                      {timeStr}
                    </span>
                    <span className="px-1.5 py-0.2 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-[10px] font-bold shrink-0 select-none">
                      [EXEC]
                    </span>
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-emerald-300 font-bold">
                          {tc.tool_name}
                        </span>
                        <span className="text-slate-300 break-all font-mono">
                          {formatToolArgs(tc.input_arguments)}
                        </span>
                        <span className="text-slate-500 text-[10px] ml-auto flex items-center gap-1.5 shrink-0">
                          {tc.duration_ms != null && <span>{tc.duration_ms}ms</span>}
                          <span
                            className={`font-semibold ${
                              isSuccess ? "text-emerald-400" : "text-rose-400"
                            }`}
                          >
                            [{tc.status.toLowerCase()}]
                          </span>
                        </span>
                      </div>

                      {/* Tool Output Stream */}
                      {formatted.lines.length > 0 && (
                        <div className="mt-1 pl-4 border-l-2 border-slate-800 space-y-0.5 text-slate-400">
                          {previewLines.map((line, idx) => (
                            <div key={idx} className="text-slate-400 whitespace-pre-wrap break-all leading-tight">
                              <span className="text-slate-600 select-none mr-2">&gt;</span>
                              {line}
                            </div>
                          ))}

                          {formatted.totalLines > 4 && (
                            <button
                              onClick={() => toggleOutputExpand(event.id)}
                              className="text-[10px] text-sky-400 hover:text-sky-300 mt-1 flex items-center gap-1 cursor-pointer select-none"
                            >
                              {isOutputExpanded ? (
                                <>
                                  <ChevronDown className="w-3 h-3" /> Fold output
                                </>
                              ) : (
                                <>
                                  <ChevronRight className="w-3 h-3" />
                                  <span>
                                    + Show {formatted.totalLines - 4} more lines
                                  </span>
                                </>
                              )}
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            }

            // 3. HUMAN-IN-THE-LOOP APPROVAL LOG / GATE
            if (event.type === "approval") {
              const gate = event.data;
              const isPending = gate.status === "PENDING";

              if (!isPending) {
                const isApproved = gate.status === "APPROVED";
                return (
                  <div key={event.id} className="px-1 py-1 flex items-start gap-2 text-xs">
                    <span className="text-slate-600 shrink-0 select-none text-[10px] mt-0.5">
                      {timeStr}
                    </span>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-bold shrink-0 select-none border ${
                        isApproved
                          ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                          : "bg-rose-950 text-rose-300 border-rose-800"
                      }`}
                    >
                      [GATE:{gate.status}]
                    </span>
                    <div className="flex-1 flex flex-wrap items-center gap-2">
                      <span className="text-slate-200">{gate.action}</span>
                      <span className="text-slate-500">on {gate.target}</span>
                      {gate.justification && (
                        <span className="text-slate-400 italic text-[11px]">
                          (Justification: &quot;{gate.justification}&quot;)
                        </span>
                      )}
                    </div>
                  </div>
                );
              }

              // PENDING APPROVAL GATE DOCK
              return (
                <div
                  key={event.id}
                  className="my-2 p-3.5 rounded-lg border border-amber-500/80 bg-amber-950/20 text-xs space-y-2 ring-1 ring-amber-500/30"
                >
                  <div className="flex items-center justify-between text-amber-300 font-bold">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-amber-400 animate-pulse" />
                      <span>[HITL GATE] OPERATOR AUTHORIZATION REQUIRED</span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded bg-amber-900/60 border border-amber-600 text-amber-200 text-[10px]">
                      {gate.risk_level} RISK
                    </span>
                  </div>

                  <div className="space-y-1 text-slate-300 pl-6 border-l-2 border-amber-500/60">
                    <div>
                      <span className="text-slate-500">Proposed Action:</span>{" "}
                      <strong className="text-sky-300 font-mono">{gate.action}</strong>
                    </div>
                    <div>
                      <span className="text-slate-500">Target Resource:</span>{" "}
                      <span className="text-slate-200 font-mono break-all">{gate.target}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Requesting Agent:</span>{" "}
                      <span className="text-slate-300">{gate.agent_id}</span>
                    </div>
                  </div>

                  {onApprovalDecision && (
                    <div className="pt-2 border-t border-amber-900/50 space-y-2">
                      <div className="flex flex-col sm:flex-row gap-2">
                        <input
                          type="text"
                          value={justifications[gate.id] || ""}
                          onChange={(e) =>
                            setJustifications({ ...justifications, [gate.id]: e.target.value })
                          }
                          placeholder="Operator audit justification (min 5 chars)..."
                          className="flex-1 px-3 py-1.5 bg-[#050811] border border-slate-700 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-amber-400 font-mono"
                        />
                        <button
                          onClick={() => handleGateAction(gate.id, "APPROVE")}
                          disabled={submittingGateId === gate.id}
                          className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-bold flex items-center justify-center gap-1 transition-colors shadow-sm disabled:opacity-50"
                        >
                          <Check className="w-3.5 h-3.5" /> Approve Action
                        </button>
                        <button
                          onClick={() => handleGateAction(gate.id, "REJECT")}
                          disabled={submittingGateId === gate.id}
                          className="px-3.5 py-1.5 bg-rose-700 hover:bg-rose-600 text-white rounded text-xs font-bold flex items-center justify-center gap-1 transition-colors shadow-sm disabled:opacity-50"
                        >
                          <X className="w-3.5 h-3.5" /> Reject Probe
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            }

            return null;
          })
        )}

        {/* Live Execution Pulse Line */}
        {isRunning && (
          <div className="flex items-center gap-2 pt-2 text-sky-400 text-xs">
            <span className="w-2 h-2 rounded-full bg-sky-400 animate-ping" />
            <span className="text-slate-400 text-[11px] font-sans">
              Agents actively evaluating attack surface vectors &amp; streaming live telemetry...
            </span>
          </div>
        )}
      </div>

      {/* 3. Stream Status Footer Bar */}
      <div className="flex items-center justify-between px-3.5 py-1.5 bg-[#050811] border-t border-slate-800/90 text-[10px] text-slate-500 select-none">
        <div className="flex items-center gap-3">
          <span>Target Scope: {workflow?.target_url || "Configured RoE Seeds"}</span>
          <span>•</span>
          <span>Logged Stream: {filteredEvents.length} events</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>Forensic Hash Chain Protected</span>
        </div>
      </div>
    </div>
  );
}

export default AgentTerminal;
