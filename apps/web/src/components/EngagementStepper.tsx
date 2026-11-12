"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Crosshair,
  Globe,
  ListChecks,
  Cpu,
  ShieldAlert,
  FileText,
  Check,
  ChevronRight,
} from "lucide-react";
import { useProject } from "@/lib/ProjectContext";

export interface StepperStep {
  id: string;
  index: number;
  label: string;
  shortLabel: string;
  summary: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
}

export const LIFECYCLE_STEPS: StepperStep[] = [
  {
    id: "scope",
    index: 1,
    label: "Scope & RoE",
    shortLabel: "1. Scope",
    summary: "Seeds & Boundaries",
    path: "/scope",
    icon: Crosshair,
  },
  {
    id: "discovery",
    index: 2,
    label: "Attack Surface",
    shortLabel: "2. Surface",
    summary: "Recon & Endpoints",
    path: "/discovery",
    icon: Globe,
  },
  {
    id: "wstg",
    index: 3,
    label: "OWASP WSTG Plan",
    shortLabel: "3. WSTG",
    summary: "106 Test Matrix",
    path: "/wstg",
    icon: ListChecks,
  },
  {
    id: "agents",
    index: 4,
    label: "Multi-Agent DAG",
    shortLabel: "4. Agents",
    summary: "LangGraph Execution",
    path: "/agents",
    icon: Cpu,
  },
  {
    id: "findings",
    index: 5,
    label: "Findings & Retest",
    shortLabel: "5. Findings",
    summary: "Forensics & PoC",
    path: "/findings",
    icon: ShieldAlert,
  },
  {
    id: "reports",
    index: 6,
    label: "PTES Report",
    shortLabel: "6. Report",
    summary: "Deliverable & Seal",
    path: "/reports",
    icon: FileText,
  },
];

interface EngagementStepperProps {
  className?: string;
  hideSummary?: boolean;
}

export function EngagementStepper({ className = "", hideSummary = false }: EngagementStepperProps) {
  const pathname = usePathname();
  const { currentProject } = useProject();

  const activeStepIndex = LIFECYCLE_STEPS.findIndex((step) =>
    pathname === step.path || pathname.startsWith(`${step.path}/`)
  );

  return (
    <nav
      aria-label="Penetration Testing Lifecycle"
      className={`bg-white border border-slate-200 rounded-xl p-2.5 sm:p-3 shadow-xs mb-6 overflow-hidden ${className}`}
    >
      <div className="flex items-center justify-between gap-2 overflow-x-auto no-scrollbar py-0.5">
        {LIFECYCLE_STEPS.map((step, idx) => {
          const isActive = idx === activeStepIndex;
          const isCompleted = activeStepIndex > -1 && idx < activeStepIndex;
          const StepIcon = step.icon;

          const content = (
            <div
              className={`flex items-center gap-2.5 px-3 py-2 rounded-lg border text-xs font-sans transition-all whitespace-nowrap select-none ${
                isActive
                  ? "bg-blue-50/80 border-blue-600 text-blue-950 font-semibold ring-1 ring-blue-500/20 shadow-xs"
                  : isCompleted
                  ? "bg-emerald-50/60 border-emerald-200 text-emerald-900 hover:bg-emerald-50"
                  : "bg-slate-50/60 border-slate-200 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
              }`}
            >
              <div
                className={`flex items-center justify-center w-6 h-6 rounded-md text-[11px] font-mono font-bold shrink-0 transition-colors ${
                  isActive
                    ? "bg-blue-600 text-white shadow-xs"
                    : isCompleted
                    ? "bg-emerald-600 text-white"
                    : "bg-white border border-slate-300 text-slate-600"
                }`}
              >
                {isCompleted ? <Check className="w-3.5 h-3.5 stroke-[2.5]" /> : step.index}
              </div>

              <div className="flex flex-col text-left">
                <div className="flex items-center gap-1.5 leading-none">
                  <StepIcon
                    className={`w-3.5 h-3.5 shrink-0 ${
                      isActive
                        ? "text-blue-700"
                        : isCompleted
                        ? "text-emerald-700"
                        : "text-slate-400"
                    }`}
                  />
                  <span className="text-xs font-medium">{step.label}</span>
                  {isActive && (
                    <span className="relative flex h-2 w-2 ml-1">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-600"></span>
                    </span>
                  )}
                </div>
                {!hideSummary && (
                  <span
                    className={`text-[10px] font-mono mt-0.5 leading-tight ${
                      isActive
                        ? "text-blue-700/80 font-normal"
                        : isCompleted
                        ? "text-emerald-700/80"
                        : "text-slate-400"
                    }`}
                  >
                    {step.summary}
                  </span>
                )}
              </div>
            </div>
          );

          return (
            <React.Fragment key={step.id}>
              {currentProject ? (
                <Link
                  href={step.path}
                  className="shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 rounded-lg"
                  title={`Navigate to ${step.label} (${step.summary})`}
                >
                  {content}
                </Link>
              ) : (
                <div
                  className="shrink-0 opacity-60 cursor-not-allowed"
                  title="Select a project in Projects directory to navigate"
                >
                  {content}
                </div>
              )}

              {idx < LIFECYCLE_STEPS.length - 1 && (
                <ChevronRight className="w-4 h-4 text-slate-300 shrink-0 mx-0.5 hidden lg:block" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </nav>
  );
}

export default EngagementStepper;

