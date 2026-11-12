"use client";

import React, { useState, useEffect } from "react";
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
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

interface NavItem {
  step?: string;
  name: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  badgeType?: "ai" | "count" | "default";
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "Engagement Lifecycle",
    items: [
      { step: "1", name: "Scope & Boundaries", href: "/scope", icon: ShieldCheck },
      { step: "2", name: "Attack Surface", href: "/discovery", icon: Globe },
      { step: "3", name: "OWASP WSTG Plan", href: "/wstg", icon: CheckSquare, badge: "106", badgeType: "count" },
      { step: "4", name: "Multi-Agent DAG", href: "/agents", icon: Bot, badge: "AI", badgeType: "ai" },
      { step: "5", name: "Findings & Retest", href: "/findings", icon: AlertTriangle },
      { step: "6", name: "PTES Reports", href: "/reports", icon: FileCheck2 },
    ],
  },
  {
    title: "Governance & Operations",
    items: [
      { name: "Overview Dashboard", href: "/", icon: LayoutDashboard },
      { name: "Audit Hash Chain", href: "/audit-logs", icon: Lock },
    ],
  },
  {
    title: "Workspace",
    items: [
      { name: "Projects Directory", href: "/projects", icon: Layers },
    ],
  },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState<boolean>(false);

  useEffect(() => {
    const saved = localStorage.getItem("pentesa_sidebar_collapsed");
    if (saved !== null) {
      setCollapsed(saved === "true");
    }
  }, []);

  const toggleCollapse = () => {
    const next = !collapsed;
    setCollapsed(next);
    localStorage.setItem("pentesa_sidebar_collapsed", String(next));
  };

  return (
    <aside
      className={`border-r border-slate-200 bg-white flex flex-col justify-between select-none transition-all duration-200 ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Navigation Sections */}
      <div className="py-3 px-2 space-y-4 overflow-y-auto">
        {NAV_SECTIONS.map((section, idx) => (
          <div key={idx} className="space-y-1">
            {!collapsed && (
              <div className="px-3 pb-1 text-[10px] font-mono uppercase tracking-wider text-slate-600 font-bold">
                {section.title}
              </div>
            )}
            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = pathname === item.href;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  title={collapsed ? item.name : undefined}
                  className={`flex items-center ${
                    collapsed ? "justify-center px-2" : "justify-between px-3"
                  } py-2 rounded text-xs font-medium transition-all group ${
                    isActive
                      ? "bg-blue-50 text-blue-900 font-semibold border-l-2 border-blue-900 shadow-xs"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-100"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon
                      className={`h-4 w-4 shrink-0 transition-colors ${
                        isActive ? "text-blue-900" : "text-slate-400 group-hover:text-slate-600"
                      }`}
                    />
                    {!collapsed && (
                      <span className="truncate">
                        {item.step && (
                          <span className="font-mono text-[11px] text-slate-500 mr-1.5 font-normal">
                            {item.step}.
                          </span>
                        )}
                        {item.name}
                      </span>
                    )}
                  </div>

                  {!collapsed && item.badge && (
                    <span
                      className={`text-[10px] px-1.5 py-0.2 rounded font-mono font-bold shrink-0 ${
                        item.badgeType === "ai"
                          ? "bg-amber-100 text-amber-900 border border-amber-300"
                          : "bg-slate-100 text-slate-700 border border-slate-200"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </div>

      {/* Footer Controls: Collapse Toggle & System Heartbeat */}
      <div className="border-t border-slate-200 bg-slate-50">
        <button
          onClick={toggleCollapse}
          className="w-full flex items-center justify-center gap-2 py-2 text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4 text-slate-500" />
          ) : (
            <div className="flex items-center gap-2">
              <ChevronLeft className="h-4 w-4 text-slate-500" />
              <span className="text-[11px] font-mono">Collapse Rail</span>
            </div>
          )}
        </button>

        {!collapsed && (
          <div className="px-3 py-2 border-t border-slate-200/80 flex items-center justify-between text-[11px] font-mono text-slate-600">
            <span className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              API: 8000
            </span>
            <span className="text-slate-600 font-semibold">v1.0-prod</span>
          </div>
        )}
      </div>
    </aside>
  );
};
