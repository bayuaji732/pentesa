"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft, ArrowRight, ShieldCheck, Lock } from "lucide-react";
import { useProject } from "@/lib/ProjectContext";

export interface StepFooterNavProps {
  currentStep: number; // 1 to 6
  nextStepPath?: string;
  nextStepLabel?: string;
  prevStepPath?: string;
  prevStepLabel?: string;
  canAdvance?: boolean;
  onAdvance?: () => Promise<boolean | void> | boolean | void;
  advanceTooltip?: string;
  customAction?: React.ReactNode;
}

export const StepFooterNav: React.FC<StepFooterNavProps> = ({
  currentStep,
  nextStepPath,
  nextStepLabel,
  prevStepPath,
  prevStepLabel,
  canAdvance = true,
  onAdvance,
  advanceTooltip,
  customAction,
}) => {
  const router = useRouter();
  const { currentProject } = useProject();
  const [submitting, setSubmitting] = useState(false);

  const handleAdvance = async () => {
    if (!canAdvance || submitting || !nextStepPath) return;

    setSubmitting(true);
    try {
      if (onAdvance) {
        const result = await onAdvance();
        if (result === false) {
          setSubmitting(false);
          return;
        }
      }

      // Record advancement in localStorage to persist unlocked step
      if (currentProject) {
        const targetStep = currentStep + 1;
        try {
          const currentUnlocked = parseInt(
            localStorage.getItem(`pentesa_unlocked_step_${currentProject.id}`) || "1",
            10
          );
          if (targetStep > currentUnlocked) {
            localStorage.setItem(
              `pentesa_unlocked_step_${currentProject.id}`,
              String(targetStep)
            );
          }
        } catch {
          // Ignore localStorage errors
        }
      }

      router.push(nextStepPath);
    } catch (err) {
      console.error("Step advancement error", err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="mt-8 pt-4 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-3 bg-white p-4 rounded-xl shadow-xs">
      <div>
        {prevStepPath ? (
          <Link
            href={prevStepPath}
            className="px-4 py-2 bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 rounded-md text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-2xs"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            <span>Back to {prevStepLabel || "Previous Step"}</span>
          </Link>
        ) : (
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-500">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
            <span>Phase 1 of 6: Pre-Engagement & Scope</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3 w-full sm:w-auto justify-end">
        {customAction}

        {nextStepPath && (
          <button
            type="button"
            onClick={handleAdvance}
            disabled={!canAdvance || submitting}
            title={
              !canAdvance
                ? advanceTooltip || "Complete required step prerequisites to proceed"
                : undefined
            }
            className={`px-5 py-2.5 rounded-md text-xs font-semibold flex items-center gap-2 shadow-xs transition-colors cursor-pointer ${
              canAdvance
                ? "bg-blue-900 hover:bg-blue-800 text-white"
                : "bg-slate-100 text-slate-400 border border-slate-200 cursor-not-allowed"
            }`}
          >
            {submitting ? (
              <>
                <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Advancing to Next Phase...</span>
              </>
            ) : !canAdvance ? (
              <>
                <Lock className="h-3.5 w-3.5" />
                <span>{nextStepLabel || "Save & Continue to Next Step"}</span>
              </>
            ) : (
              <>
                <span>{nextStepLabel || "Save & Continue to Next Step"}</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
};

