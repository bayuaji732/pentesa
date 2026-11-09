"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  ShieldCheck,
  Globe,
  CheckSquare,
  Bot,
  AlertTriangle,
  FileCheck2,
  Lock,
  Layers,
} from "lucide-react";

interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Scope & Boundaries", href: "/scope", icon: ShieldCheck },
  { name: "Attack Surface", href: "/discovery", icon: Globe },
  { name: "OWASP WSTG Plan", href: "/wstg", icon: CheckSquare, badge: "106" },
  { name: "Multi-Agent DAG", href: "/agents", icon: Bot, badge: "AI" },
  { name: "Findings & Retest", href: "/findings", icon: AlertTriangle },
  { name: "PTES Reports", href: "/reports", icon: FileCheck2 },
  { name: "Audit Hash Chain", href: "/audit-logs", icon: Lock },
  { name: "Projects", href: "/projects", icon: Layers },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  return (
    <aside className="w-60 border-r border-slate-800 bg-surface-base flex flex-col justify-between select-none">
      <div className="py-3 px-2 space-y-1">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold">
          Platform Operations
        </div>
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-all ${
                isActive
                  ? "bg-slate-800 text-slate-100 font-semibold border-l-2 border-red-500"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`h-4 w-4 ${isActive ? "text-red-400" : "text-slate-400"}`} />
                <span>{item.name}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-bold ${
                    item.badge === "AI"
                      ? "bg-cyan-950 text-cyan-400 border border-cyan-800"
                      : "bg-slate-800 text-slate-300"
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </div>

      {/* Footer System Status Indicator */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-900/40">
        <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            Core API: 8000
          </span>
          <span className="text-slate-500">v1.0-prod</span>
        </div>
      </div>
    </aside>
  );
};

