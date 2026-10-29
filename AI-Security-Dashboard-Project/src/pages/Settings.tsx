/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  User,
  Shield,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Server,
  LogOut,
  Mail,
  HardDrive,
  Calendar,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { NoticeBanner } from '../components/common/NoticeBanner';

export const Settings: React.FC = () => {
  const { currentUser, updateUserProfile, logout, authorizedScopeConsent, setAuthorizedScopeConsent, uploadedFiles } = useSecurity();
  const navigate = useNavigate();

  const [name, setName] = useState(currentUser?.name || '');
  const [role, setRole] = useState(currentUser?.role || 'Security Analyst');
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    await updateUserProfile({ name, role });
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  // Calculate total uploaded storage
  const totalBytes = uploadedFiles.reduce((acc, f) => acc + (f.fileSizeBytes || 0), 0);
  const totalMB = (totalBytes / (1024 * 1024)).toFixed(2);
  const storagePercentage = Math.min(100, Math.round((totalBytes / (100 * 1024 * 1024)) * 100));

  return (
    <div className="space-y-6 max-w-4xl">
      <NoticeBanner
        type="demo"
        customMessage="Profile & Workspace Settings: Manage your personal account details, file storage, and security scanning preferences."
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 tracking-tight">
            Account Profile & Settings
          </h1>
          <p className="text-xs text-zinc-400">
            View your profile, update your personal info, and manage your security workspace
          </p>
        </div>

        {/* Prominent Log Out Button */}
        <button
          type="button"
          onClick={() => setShowLogoutConfirm(true)}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-red-950/70 hover:bg-red-900 text-red-300 border border-red-800 text-xs font-semibold transition-colors self-start sm:self-auto cursor-pointer"
        >
          <LogOut className="w-4 h-4" />
          <span>Log Out</span>
        </button>
      </div>

      {/* Active User Profile Card */}
      <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-600 to-blue-700 border border-cyan-500/40 flex items-center justify-center font-bold text-base text-white shadow-md">
              {currentUser?.avatarInitials || 'US'}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-zinc-100 text-base">{currentUser?.name || 'User'}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
                  {currentUser?.role || 'Member'}
                </span>
              </div>
              <p className="text-xs text-zinc-400 flex items-center gap-1 mt-0.5">
                <Mail className="w-3.5 h-3.5 text-zinc-500" />
                <span>{currentUser?.email || 'user@example.com'}</span>
              </p>
            </div>
          </div>

          <div className="text-left sm:text-right text-xs text-zinc-400">
            <div className="flex items-center gap-1.5 text-emerald-400 sm:justify-end">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              <span className="font-semibold">Active & Logged In</span>
            </div>
            <p className="text-[11px] text-zinc-500 mt-1 flex items-center gap-1 sm:justify-end">
              <Calendar className="w-3 h-3" />
              <span>Session started: {currentUser?.loginTime || 'Today'}</span>
            </p>
          </div>
        </div>

        {/* 3 Overview Info Badges */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
            <span className="text-[11px] text-zinc-500 block">Account Email</span>
            <span className="text-zinc-200 font-semibold truncate block">{currentUser?.email || 'N/A'}</span>
          </div>

          <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
            <span className="text-[11px] text-zinc-500 block">Assigned Role</span>
            <span className="text-cyan-300 font-semibold">{currentUser?.role || 'Security Analyst'}</span>
          </div>

          <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="flex justify-between items-center text-[11px] text-zinc-500">
              <span>Cloud Storage Used</span>
              <span>{storagePercentage}%</span>
            </div>
            <span className="text-zinc-200 font-semibold block">{totalMB} MB / 100 MB</span>
          </div>
        </div>
      </div>

      {/* Logout Confirmation Dialog */}
      {showLogoutConfirm && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-sm bg-zinc-950 border border-zinc-800 rounded-xl p-5 shadow-2xl space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <AlertTriangle className="w-6 h-6 shrink-0" />
              <h3 className="font-bold text-sm text-zinc-100">Log Out Confirmation</h3>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed">
              Are you sure you want to log out of your account? You can log back in at any time with your email ({currentUser?.email}).
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setShowLogoutConfirm(false)}
                className="px-3.5 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs cursor-pointer"
              >
                Stay Logged In
              </button>
              <button
                type="button"
                onClick={handleLogout}
                className="px-4 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white font-semibold text-xs cursor-pointer"
              >
                Yes, Log Out
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Profile Form */}
      <form onSubmit={handleSaveProfile} className="space-y-6">
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-zinc-800">
            <User className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Edit Profile Information
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="space-y-1">
              <label className="font-semibold text-zinc-300">Your Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Enter your name"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500 text-xs"
              />
            </div>

            <div className="space-y-1">
              <label className="font-semibold text-zinc-300">Your Role / Job Title</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500 text-xs"
              >
                <option value="Security Analyst">Security Analyst</option>
                <option value="Security Manager">Security Manager</option>
                <option value="System Administrator">System Administrator</option>
                <option value="Software Developer">Software Developer</option>
                <option value="IT Specialist">IT Specialist</option>
                <option value="Personal User">Personal User</option>
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2">
            {saveSuccess ? (
              <span className="text-xs text-emerald-400 flex items-center gap-1.5 font-medium">
                <CheckCircle2 className="w-4 h-4" />
                Profile updated successfully!
              </span>
            ) : (
              <span />
            )}

            <button
              type="submit"
              className="px-4 py-2 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold tracking-wide transition-colors shadow-sm cursor-pointer"
            >
              Save Changes
            </button>
          </div>
        </div>

        {/* Security Guardrails & Cloud Storage Settings */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center gap-2 pb-2 border-b border-zinc-800">
            <Shield className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-200">
              Workspace & Security Preferences
            </h2>
          </div>

          <div className="space-y-3 text-xs">
            <label className="flex items-start gap-3 p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 cursor-pointer">
              <input
                type="checkbox"
                checked={authorizedScopeConsent}
                onChange={(e) => setAuthorizedScopeConsent(e.target.checked)}
                className="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-cyan-600 focus:ring-cyan-500"
              />
              <div className="space-y-0.5">
                <span className="font-semibold text-zinc-200 block">
                  Safe Scope Protection (Recommended)
                </span>
                <p className="text-zinc-400 text-xs">
                  Restricts network port scans to your authorized private network (e.g. 192.168.x.x, 10.x.x.x, localhost) to prevent scanning external public internet addresses.
                </p>
              </div>
            </label>

            <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-zinc-200">Cloud file storage</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-800">
                  NOT CONFIGURED
                </span>
              </div>
              <p className="text-zinc-400 text-xs">
                Files are analyzed locally in this browser session. No cloud bucket is configured, so files are not uploaded or stored remotely.
              </p>
            </div>
          </div>
        </div>
      </form>
    </div>
  );
};
