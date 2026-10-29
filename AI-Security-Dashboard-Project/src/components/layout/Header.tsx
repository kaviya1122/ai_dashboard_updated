/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Clock, Search, Bell, Menu, LogOut, User } from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

interface HeaderProps {
  onToggleSidebar?: () => void;
  onSearch?: (query: string) => void;
}

export const Header: React.FC<HeaderProps> = ({ onToggleSidebar, onSearch }) => {
  const { alerts, currentUser, logout } = useSecurity();
  const navigate = useNavigate();
  const [currentTime, setCurrentTime] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const criticalCount = alerts.filter((a) => a.severity === 'critical' && a.status !== 'resolved').length;
  const highCount = alerts.filter((a) => a.severity === 'high' && a.status !== 'resolved').length;

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(e.target.value);
    if (onSearch) onSearch(e.target.value);
  };

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <header className="sticky top-0 z-30 bg-zinc-950/95 backdrop-blur border-b border-zinc-800 text-zinc-200">
      <div className="px-4 lg:px-6 h-16 flex items-center justify-between gap-4">
        {/* Left: Mobile hamburger & Clean Title */}
        <div className="flex items-center gap-3">
          <button
            onClick={onToggleSidebar}
            aria-label="Toggle navigation menu"
            className="p-2 rounded-lg text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 lg:hidden focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center shadow-md">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm tracking-wide text-zinc-100">
                  AI Security Hub
                </span>
                <span className="hidden sm:inline-block text-[11px] font-medium px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800/80">
                  Live Protection
                </span>
              </div>
              <p className="text-[10px] text-zinc-400 tracking-wide hidden sm:block">
                Simple & Reliable Threat Monitoring
              </p>
            </div>
          </div>
        </div>

        {/* Center: Search input */}
        <div className="hidden md:flex flex-1 max-w-md mx-4">
          <div className="relative w-full">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              placeholder="Search files, IP addresses, threat alerts..."
              value={searchQuery}
              onChange={handleSearchChange}
              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/80 transition-colors"
            />
          </div>
        </div>

        {/* Right: Status, User Name & Quick Logout */}
        <div className="flex items-center gap-3">
          {/* Threat status pill */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-zinc-900 border border-zinc-800 text-xs">
            <span
              className={`w-2 h-2 rounded-full ${
                criticalCount > 0 ? 'bg-red-500 animate-pulse' : highCount > 0 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              aria-hidden="true"
            />
            <span className="text-zinc-300 text-xs font-medium">
              {criticalCount > 0
                ? `${criticalCount} Urgent Threat`
                : highCount > 0
                ? `${highCount} Threats Found`
                : 'All Systems Protected'}
            </span>
          </div>

          {/* Time */}
          <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-zinc-900 border border-zinc-800 text-xs text-zinc-300">
            <Clock className="w-3.5 h-3.5 text-zinc-400" />
            <span className="text-[11px]">{currentTime}</span>
          </div>

          {/* Notifications */}
          <button
            onClick={() => navigate('/alerts')}
            aria-label="View notifications"
            className="relative p-2 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 cursor-pointer"
          >
            <Bell className="w-4 h-4" />
            {criticalCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 bg-red-600 text-white rounded-full text-[10px] font-bold flex items-center justify-center">
                {criticalCount}
              </span>
            )}
          </button>

          {/* User profile capsule & Logout button */}
          <div className="flex items-center gap-2 pl-2 border-l border-zinc-800">
            <button
              onClick={() => navigate('/settings')}
              className="flex items-center gap-2 p-1 rounded-lg hover:bg-zinc-900 transition-colors text-left cursor-pointer"
              title="Go to Profile"
            >
              <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center text-xs font-bold text-white shadow-xs">
                {currentUser?.avatarInitials || 'US'}
              </div>
              <div className="hidden xl:block">
                <span className="text-xs font-semibold text-zinc-200 block truncate max-w-[120px]">
                  {currentUser?.name || 'My Account'}
                </span>
                <span className="text-[10px] text-zinc-400 block truncate max-w-[120px]">
                  {currentUser?.email || 'Profile'}
                </span>
              </div>
            </button>

            {/* Direct Logout Icon Button */}
            <button
              onClick={handleLogout}
              title="Log Out"
              aria-label="Log Out"
              className="p-1.5 rounded-lg text-zinc-400 hover:text-red-400 hover:bg-red-950/40 border border-transparent hover:border-red-900/50 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
