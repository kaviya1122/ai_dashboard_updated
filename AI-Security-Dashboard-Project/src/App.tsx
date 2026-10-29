/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { SecurityProvider, useSecurity } from './context/SecurityContext';
import { Header } from './components/layout/Header';
import { Sidebar } from './components/layout/Sidebar';
import { AlertDetailModal } from './components/alerts/AlertDetailModal';
import { LiveThreatStream } from './components/common/LiveThreatStream';
import { PlaybookExecutionModal } from './components/common/PlaybookExecutionModal';

// Pages
import { Overview } from './pages/Overview';
import { Analytics } from './pages/Analytics';
import { Alerts } from './pages/Alerts';
import { Assets } from './pages/Assets';
import { UploadCenter } from './pages/UploadCenter';
import { Scanners } from './pages/Scanners';
import { Copilot } from './pages/Copilot';
import { Reports } from './pages/Reports';
import { Statistics } from './pages/Statistics';
import { Settings } from './pages/Settings';
import { ThreatIntel } from './pages/ThreatIntel';
import { Login } from './pages/Login';

function DashboardLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [globalPlaybookOpen, setGlobalPlaybookOpen] = useState(false);
  const { isAuthenticated } = useSecurity();
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans antialiased selection:bg-cyan-900 selection:text-cyan-100">
      {/* Top SOC Navigation Header */}
      <Header onToggleSidebar={() => setSidebarOpen((prev) => !prev)} />

      {/* Public threat intelligence status across all views */}
      <LiveThreatStream />

      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar Navigation */}
        <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

        {/* Main Analyst Workspace Content Area */}
        <main
          id="main-content"
          className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-zinc-950"
        >
          <div className="max-w-7xl mx-auto">
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/overview" element={<Navigate to="/" replace />} />
              <Route path="/analytics" element={<Analytics />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/upload" element={<UploadCenter />} />
              <Route path="/scanners" element={<Scanners />} />
              <Route path="/copilot" element={<Copilot />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/network" element={<Navigate to="/scanners" replace />} />
              <Route path="/statistics" element={<Statistics />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </main>
      </div>

      {/* Global Alert Investigation Modal */}
      <AlertDetailModal />

      {/* Global SOAR Playbook Execution Modal */}
      <PlaybookExecutionModal
        isOpen={globalPlaybookOpen}
        onClose={() => setGlobalPlaybookOpen(false)}
      />
    </div>
  );
}

export default function App() {
  return (
    <SecurityProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/*" element={<DashboardLayout />} />
        </Routes>
      </BrowserRouter>
    </SecurityProvider>
  );
}
