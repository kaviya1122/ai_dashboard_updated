/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  LineChart,
  ShieldAlert,
  Server,
  UploadCloud,
  Crosshair,
  Bot,
  FileText,
  BarChart3,
  Radar,
  Settings,
  X,
  LogOut,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const { alerts, scans, currentUser, logout } = useSecurity();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const openIncidentsCount = alerts.filter(
    (a) => a.status === 'new' || a.status === 'investigating'
  ).length;

  const navItems = [
    { name: 'Dashboard', to: '/', icon: LayoutDashboard },
    { name: 'Visual Analytics', to: '/analytics', icon: LineChart },
    { name: 'Global Threat Intel', to: '/threat-intel', icon: Radar },
    {
      name: 'Threat Alerts',
      to: '/alerts',
      icon: ShieldAlert,
      badge: openIncidentsCount > 0 ? openIncidentsCount : undefined,
      badgeColor: 'bg-red-950 text-red-300 border-red-800',
    },
    { name: 'Protected Devices', to: '/assets', icon: Server },
    { name: 'File Scanner (100MB)', to: '/upload', icon: UploadCloud },
    {
      name: 'Quick Scanners',
      to: '/scanners',
      icon: Crosshair,
      badge: scans.length > 0 ? scans.length : undefined,
      badgeColor: 'bg-zinc-800 text-zinc-300 border-zinc-700',
    },
    {
      name: 'AI Security Assistant',
      to: '/copilot',
      icon: Bot,
      highlight: true,
    },
    { name: 'Security Reports', to: '/reports', icon: FileText },
    { name: 'Statistics', to: '/statistics', icon: BarChart3 },
    { name: 'Profile & Settings', to: '/settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/70 z-40 lg:hidden backdrop-blur-xs transition-opacity"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-64 bg-zinc-950 border-r border-zinc-800 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:static lg:z-auto`}
        aria-label="Navigation"
      >
        {/* Mobile Header in sidebar */}
        <div className="flex items-center justify-between p-4 border-b border-zinc-800 lg:hidden">
          <span className="font-bold text-xs uppercase tracking-wider text-zinc-200">
            Navigation Menu
          </span>
          <button
            onClick={onClose}
            aria-label="Close menu"
            className="p-1 rounded text-zinc-400 hover:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Section Label */}
        <div className="px-4 pt-4 pb-2 text-[11px] font-semibold uppercase tracking-wider text-zinc-400">
          Security Modules
        </div>

        {/* Navigation list */}
        <nav className="flex-1 px-3 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => {
                  if (window.innerWidth < 1024) onClose();
                }}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all duration-100 outline-none ${
                    isActive
                      ? 'bg-zinc-850 text-cyan-400 border border-zinc-700 shadow-xs'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                  } ${
                    item.highlight && !item.to.includes('active')
                      ? 'border-cyan-900/40 hover:border-cyan-800/60'
                      : ''
                  }`
                }
              >
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      item.highlight ? 'text-cyan-400' : 'text-zinc-400 group-hover:text-zinc-200'
                    }`}
                  />
                  <span>{item.name}</span>
                </div>
                {item.badge !== undefined && (
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border ${item.badgeColor}`}
                  >
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* User Account Card with Logout */}
        <div className="p-3.5 border-t border-zinc-800/80 bg-zinc-900/40">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center text-xs font-bold text-white shrink-0">
                {currentUser?.avatarInitials || 'US'}
              </div>
              <div className="min-w-0">
                <p className="text-xs font-semibold text-zinc-200 truncate">
                  {currentUser?.name || 'User'}
                </p>
                <p className="text-[10px] text-zinc-400 truncate">
                  {currentUser?.email || currentUser?.role || 'Logged in'}
                </p>
              </div>
            </div>

            <button
              onClick={handleLogout}
              title="Log Out"
              aria-label="Log Out"
              className="p-1.5 rounded-md text-zinc-400 hover:text-red-400 hover:bg-red-950/40 border border-transparent hover:border-red-900/50 transition-colors shrink-0 cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>

          <div className="mt-2 pt-2 border-t border-zinc-800/60 flex items-center justify-between text-[11px] text-zinc-400">
            <span className="flex items-center gap-1.5 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span>Online</span>
            </span>
            <button
              onClick={handleLogout}
              className="text-red-400 hover:text-red-300 hover:underline cursor-pointer"
            >
              Log Out
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};
