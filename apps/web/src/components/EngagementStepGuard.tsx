"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { Lock, ArrowRight, Layers, ShieldAlert } from "lucide-react";
import { useProject } from "@/lib/ProjectContext";
import { getUnlockedStep, LIFECYCLE_STEPS, EngagementStepper } from "@/components/EngagementStepper";

interface EngagementStepGuardProps {
  requiredStep: number; // 2 to 6
  stepTitle?: string;
  children: React.ReactNode;
}

export const EngagementStepGuard: React.FC<EngagementStepGuardProps> = ({
  requiredStep,
  stepTitle,
  children,
}) => {
  const { currentProject, loading } = useProject();
  const [mounted, setMounted] = useState(false);
  const [unlockedStep, setUnlockedStep] = useState<number>(1);

  useEffect(() => {
    setMounted(true);
    if (currentProject) {
      setUnlockedStep(getUnlockedStep(currentProject));
    }
  }, [currentProject]);

  if (loading || !mounted) {
    return (
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center text-xs font-mono text-slate-400 bg-white border border-slate-200 rounded-xl shadow-xs">
          Validating engagement access policies...
        </div>
      </div>
    );
  }

  if (!currentProject) {
    return (
      <div className="space-y-6">
        <EngagementStepper />
        <div className="p-12 text-center bg-white border border-slate-200 rounded-xl shadow-xs max-w-xl mx-auto">
          <Layers className="w-10 h-10 text-slate-300 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-800">No Engagement Selected</h3>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            Please select or initialize a penetration testing engagement from the directory to access this phase.
          </p>
          <div className="mt-4">
            <Link
              href="/projects"
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-blue-900 hover:bg-blue-800 text-xs font-semibold text-white shadow-xs transition-colors"
            >
              <span>Go to Engagements Directory</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </div>
    );
  }

  // Phase Locked Check
  if (unlockedStep < requiredStep) {
    const activeStepMeta = LIFECYCLE_STEPS.find((s) => s.index === unlockedStep) || LIFECYCLE_STEPS[0];
    const targetStepMeta = LIFECYCLE_STEPS.find((s) => s.index === requiredStep) || LIFECYCLE_STEPS[requiredStep - 1];

    return (
      <div className="space-y-6">
        <EngagementStepper unlockedLevel={unlockedStep} />

        <div className="max-w-2xl mx-auto bg-white border border-slate-200 rounded-xl p-8 shadow-xs text-center">
          <div className="w-12 h-12 rounded-full bg-amber-50 border border-amber-200 flex items-center justify-center mx-auto mb-4 text-amber-600">
            <Lock className="w-6 h-6" />
          </div>

          <span className="text-[10px] font-mono font-semibold uppercase px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
            Phase Locked · Lifecycle Policy Enforced
          </span>

          <h2 className="text-base font-bold text-slate-900 mt-3">
            Step {requiredStep}: {stepTitle || targetStepMeta?.label} is Locked
          </h2>

          <p className="text-xs text-slate-600 mt-2 max-w-lg mx-auto leading-relaxed">
            This penetration testing phase requires completion of prior upstream stages. Direct navigation bypass is restricted to uphold PTES methodology and Rules of Engagement integrity.
          </p>

          <div className="mt-6 p-4 bg-slate-50 rounded-lg border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-left text-xs">
            <div>
              <div className="text-[11px] font-medium text-slate-500">Active Unlocked Stage:</div>
              <div className="font-semibold text-slate-800 mt-0.5 flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse" />
                Step {unlockedStep}: {activeStepMeta.label}
              </div>
            </div>
            <Link
              href={activeStepMeta.path}
              className="px-4 py-2 bg-blue-900 hover:bg-blue-800 text-white rounded-md text-xs font-semibold flex items-center justify-center gap-1.5 shadow-xs transition-colors shrink-0"
            >
              <span>Continue Step {unlockedStep}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-center gap-4 text-xs">
            <Link
              href="/projects"
              className="text-slate-500 hover:text-slate-800 font-medium transition-colors"
            >
              &larr; Switch Engagement in Directory
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

