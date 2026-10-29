/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Server,
  ArrowRight,
  Bot,
  CheckCircle,
  AlertTriangle,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { IncidentStatus, SeverityLevel } from '../types';

export const Alerts: React.FC = () => {
  const { alerts, openAlertModal, updateAlertStatus } = useSecurity();

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter) return false;
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (categoryFilter !== 'all' && alert.category !== categoryFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        alert.id.toLowerCase().includes(q) ||
        alert.title.toLowerCase().includes(q) ||
        alert.affectedAsset.toLowerCase().includes(q) ||
        alert.assetIp.toLowerCase().includes(q) ||
        (alert.mitreTechnique && alert.mitreTechnique.toLowerCase().includes(q));
      if (!match) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <NoticeBanner
        type="demo"
        customMessage="Sample incident records for demonstration only. Connect a SIEM, EDR, or firewall feed to display live alerts."
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-zinc-100 tracking-tight">
            Incident & Alert Management Queue
          </h1>
          <p className="text-xs text-zinc-400">
            Triage, investigate, and contain security events across enterprise infrastructure
          </p>
        </div>

        <div className="text-xs font-mono text-zinc-400">
          Total Incidents: <strong className="text-zinc-200">{alerts.length}</strong> (
          <strong className="text-red-400">{alerts.filter((a) => a.severity === 'critical').length} Critical</strong>)
        </div>
      </div>

      {/* Filter Bar */}
      <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-4 shadow-xs space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              placeholder="Search alert ID, title, IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 pl-8 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Informational</option>
          </select>

          {/* Status */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Incident Statuses</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>

          {/* Category */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Categories</option>
            <option value="command_and_control">Command and Control</option>
            <option value="credential_access">Credential Access</option>
            <option value="exfiltration">Exfiltration</option>
            <option value="policy_violation">Policy Violation</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg overflow-hidden shadow-xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950 text-zinc-400 font-mono text-[11px] uppercase border-b border-zinc-800">
              <tr>
                <th className="py-3 px-4 font-medium">Severity</th>
                <th className="py-3 px-4 font-medium">Incident & MITRE Technique</th>
                <th className="py-3 px-4 font-medium">Affected Asset</th>
                <th className="py-3 px-4 font-medium">Detection Source</th>
                <th className="py-3 px-4 font-medium">Confidence</th>
                <th className="py-3 px-4 font-medium">Status</th>
                <th className="py-3 px-4 font-medium text-right">Investigation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/80 bg-zinc-900/40">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-zinc-500 font-mono">
                    No alerts matching current filter parameters.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => openAlertModal(alert)}
                    className="hover:bg-zinc-800/40 cursor-pointer transition-colors group"
                  >
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 font-medium text-zinc-200">
                      <div className="font-semibold text-zinc-100 group-hover:text-cyan-400 transition-colors">
                        {alert.title}
                      </div>
                      <div className="text-[11px] font-mono text-zinc-400">
                        {alert.id} • {alert.mitreTechnique || 'Unmapped'}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono">
                      <div className="flex items-center gap-1.5 text-zinc-300">
                        <Server className="w-3.5 h-3.5 text-cyan-400" />
                        <span>{alert.affectedAsset}</span>
                      </div>
                      <div className="text-[11px] text-zinc-400">{alert.assetIp}</div>
                    </td>
                    <td className="py-3.5 px-4 text-zinc-400 max-w-xs truncate">{alert.source}</td>
                    <td className="py-3.5 px-4 font-mono text-zinc-300">{alert.confidence}%</td>
                    <td className="py-3.5 px-4">
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openAlertModal(alert);
                        }}
                        className="px-3 py-1 rounded bg-zinc-800 hover:bg-cyan-950 hover:text-cyan-300 hover:border-cyan-700 text-zinc-200 border border-zinc-700 text-xs font-medium transition-colors"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
