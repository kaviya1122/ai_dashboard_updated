/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  X,
  Server,
  Network,
  Bot,
  FilePlus2,
  Clock,
  Shield,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
  Crosshair,
  ExternalLink,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { IncidentStatus } from '../../types';

export const AlertDetailModal: React.FC = () => {
  const {
    activeAlertForModal,
    closeAlertModal,
    updateAlertStatus,
    setCopilotContext,
    addReport,
    scans,
  } = useSecurity();
  const navigate = useNavigate();

  if (!activeAlertForModal) return null;

  const alert = activeAlertForModal;

  const handleSendToCopilot = () => {
    setCopilotContext({
      type: 'alert',
      id: alert.id,
      title: alert.title,
      summary: `${alert.description} [Asset: ${alert.affectedAsset} (${alert.assetIp}), Severity: ${alert.severity.toUpperCase()}, MITRE: ${alert.mitreTechnique || 'N/A'}]`,
    });
    closeAlertModal();
    navigate('/copilot');
  };

  const handleAnalyzeIpInScanner = () => {
    closeAlertModal();
    navigate('/scanners', { state: { prefillTarget: alert.assetIp } });
  };

  const handleCreateReportFromAlert = () => {
    const newReport = {
      id: `REP-${alert.id}-${Date.now().toString(36).slice(-4).toUpperCase()}`,
      title: `Incident Investigation Report: ${alert.title}`,
      classification: 'TLP:AMBER' as const,
      type: 'incident_triage' as const,
      createdAt: new Date().toISOString(),
      author: 'Dashboard User',
      associatedAlertIds: [alert.id],
      associatedScanIds: [],
      evidenceItems: alert.evidence.map((ev) => ({
        source: `Alert ${alert.id} (${alert.affectedAsset})`,
        indicator: `${ev.key}: ${ev.value}${ev.note ? ` [${ev.note}]` : ''}`,
        severity: alert.severity,
        timestamp: alert.timestamp,
        verificationStatus: 'sample_data' as const,
      })),
      aiAssistanceNotes: [
        `Automated initial triage for ${alert.title}. Recommend host containment on subnet ${alert.assetIp}.`,
        'DISCLAIMER: AI suggestions are non-authoritative triage assistance.',
      ],
      analystConclusions: `Incident ${alert.id} is based on a sample alert record. Response status has not been verified. Primary affected asset in the sample: ${alert.affectedAsset}.`,
      actionItems: alert.recommendedActions.map((act, i) => ({
        action: act,
        assignedTo: 'Not assigned',
        dueDate: new Date(Date.now() + (i + 1) * 3600 * 1000).toISOString(),
        status: 'pending' as const,
      })),
    };
    addReport(newReport);
    closeAlertModal();
    navigate('/reports');
  };

  const statusOptions: IncidentStatus[] = ['new', 'investigating', 'contained', 'resolved', 'false_positive'];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-black/80 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="alert-modal-title"
    >
      <div className="relative w-full max-w-4xl bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden flex flex-col my-auto max-h-[92vh]">
        {/* Modal Header */}
        <div className="px-6 py-4 bg-zinc-900 border-b border-zinc-800 flex items-start justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-xs text-zinc-400 font-semibold">{alert.id}</span>
              <SeverityBadge severity={alert.severity} size="sm" />
              <StatusBadge status={alert.status} />
              <span className="text-xs text-zinc-400 font-mono">
                Confidence: <strong className="text-zinc-200">{alert.confidence}%</strong>
              </span>
            </div>
            <h2 id="alert-modal-title" className="text-lg font-bold text-zinc-100 tracking-tight">
              {alert.title}
            </h2>
          </div>

          <button
            onClick={closeAlertModal}
            aria-label="Close alert details dialog"
            className="p-1.5 rounded-md text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-zinc-300">
          {/* Top Metadata Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3.5 bg-zinc-900/70 border border-zinc-800/80 rounded-lg">
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400 block">Affected Asset</span>
              <div className="flex items-center gap-1.5 mt-0.5 text-zinc-200 font-semibold">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                <span>{alert.affectedAsset}</span>
              </div>
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400 block">Asset IP</span>
              <span className="text-zinc-200 font-mono mt-0.5 block">{alert.assetIp}</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400 block">Detection Source</span>
              <span className="text-zinc-200 truncate mt-0.5 block">{alert.source}</span>
            </div>
            <div>
              <span className="text-[10px] uppercase font-mono text-zinc-400 block">MITRE Technique</span>
              <span className="text-cyan-300 font-mono mt-0.5 block truncate">
                {alert.mitreTechnique || 'Unmapped'}
              </span>
            </div>
          </div>

          {/* Description */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-1.5">
              Incident Synopsis
            </h3>
            <p className="text-sm text-zinc-200 leading-relaxed bg-zinc-900/40 p-3.5 rounded-lg border border-zinc-800/60">
              {alert.description}
            </p>
          </div>

          {/* Evidence Grid */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">
              Verifiable Evidence Artifacts (Deterministic Logs)
            </h3>
            <div className="divide-y divide-zinc-800/80 border border-zinc-800 rounded-lg overflow-hidden bg-zinc-900/30">
              {alert.evidence.map((ev, index) => (
                <div key={index} className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <span className="font-mono text-zinc-400 font-medium text-xs">{ev.key}</span>
                  <div className="text-right sm:max-w-md">
                    <span className="font-mono text-xs text-zinc-200 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800 inline-block">
                      {ev.value}
                    </span>
                    {ev.note && <p className="text-[11px] text-zinc-400 mt-0.5">{ev.note}</p>}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Timeline */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-zinc-400" />
              Event Chronology
            </h3>
            <div className="relative pl-6 space-y-3 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-zinc-800">
              {alert.timeline.map((item, idx) => (
                <div key={idx} className="relative">
                  <span className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-500 ring-4 ring-zinc-950" />
                  <div className="text-xs">
                    <span className="font-mono text-cyan-400 font-semibold">{item.time}</span> —{' '}
                    <span className="text-zinc-200">{item.event}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recommended Next Steps */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-2">
              Standard Operating Procedure (SOP) Actions
            </h3>
            <ul className="space-y-1.5">
              {alert.recommendedActions.map((action, i) => (
                <li
                  key={i}
                  className="flex items-start gap-2 p-2.5 rounded bg-zinc-900/40 border border-zinc-800/60 text-xs text-zinc-200"
                >
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{action}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Status Changer */}
          <div className="pt-2 border-t border-zinc-800/80 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-zinc-400">Update Status:</span>
              <div className="flex flex-wrap gap-1">
                {statusOptions.map((st) => (
                  <button
                    key={st}
                    onClick={() => updateAlertStatus(alert.id, st)}
                    className={`px-2 py-1 rounded text-xs font-mono capitalize transition-colors ${
                      alert.status === st
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-semibold'
                        : 'bg-zinc-900 text-zinc-400 hover:bg-zinc-800 border border-zinc-800'
                    }`}
                  >
                    {st.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer with Deep Links */}
        <div className="px-6 py-4 bg-zinc-900 border-t border-zinc-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleSendToCopilot}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <Bot className="w-3.5 h-3.5" />
              Ask Copilot About Alert
            </button>

            <button
              onClick={handleAnalyzeIpInScanner}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-850 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <Network className="w-3.5 h-3.5 text-zinc-400" />
              Scan Host IP ({alert.assetIp})
            </button>

            <button
              onClick={handleCreateReportFromAlert}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-850 hover:bg-zinc-800 text-zinc-200 border border-zinc-700 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <FilePlus2 className="w-3.5 h-3.5 text-zinc-400" />
              Generate Incident Report
            </button>
          </div>

          <button
            onClick={closeAlertModal}
            className="px-4 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium border border-zinc-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
