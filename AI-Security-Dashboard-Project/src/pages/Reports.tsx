/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  FileText,
  Plus,
  Download,
  Copy,
  Check,
  Shield,
  Clock,
  Printer,
  ChevronRight,
  AlertCircle,
  Sparkles,
  Info,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { compileIncidentReport, renderReportToMarkdown } from '../utils/reportCompiler';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { ReportItem } from '../types';

export const Reports: React.FC = () => {
  const { reports, alerts, scans, addReport, updateReport } = useSecurity();

  const [selectedReport, setSelectedReport] = useState<ReportItem | null>(reports[0] || null);
  const [isCreatingReport, setIsCreatingReport] = useState(false);
  const [copiedSuccess, setCopiedSuccess] = useState(false);

  // Form state for creating a new report
  const [reportTitle, setReportTitle] = useState('');
  const [reportType, setReportType] = useState<ReportItem['type']>('incident_triage');
  const [reportClassification, setReportClassification] = useState<ReportItem['classification']>('TLP:AMBER');
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [selectedScanIds, setSelectedScanIds] = useState<string[]>([]);
  const [analystNotes, setAnalystNotes] = useState('');

  const handleGenerateReport = (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportTitle.trim()) return;

    const matchedAlerts = alerts.filter((a) => selectedAlertIds.includes(a.id));
    const matchedScans = scans.filter((s) => selectedScanIds.includes(s.id));

    const newReport = compileIncidentReport({
      title: reportTitle.trim(),
      type: reportType,
      classification: reportClassification,
      alerts: matchedAlerts,
      scans: matchedScans,
      analystConclusions:
        analystNotes.trim() ||
        'No containment action has been verified. Record the action and supporting evidence after handling it in your security product.',
    });

    addReport(newReport);
    setSelectedReport(newReport);
    setIsCreatingReport(false);
    setReportTitle('');
    setSelectedAlertIds([]);
    setSelectedScanIds([]);
    setAnalystNotes('');
  };

  const handleActionStatusChange = (actionIndex: number, status: ReportItem['actionItems'][number]['status']) => {
    if (!selectedReport) return;
    const updatedReport = {
      ...selectedReport,
      actionItems: selectedReport.actionItems.map((item, index) => index === actionIndex ? { ...item, status } : item),
    };
    updateReport(updatedReport);
    setSelectedReport(updatedReport);
  };

  const handleCopyMarkdown = () => {
    if (!selectedReport) return;
    const md = renderReportToMarkdown(selectedReport);
    navigator.clipboard.writeText(md).then(() => {
      setCopiedSuccess(true);
      setTimeout(() => setCopiedSuccess(false), 2000);
    });
  };

  const handleDownloadJson = () => {
    if (!selectedReport) return;
    const blob = new Blob([JSON.stringify(selectedReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedReport.id}_report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <NoticeBanner
        type="ai_disclaimer"
        customMessage="Reports compile actual findings with strict boundary separation: Telemetry Artifacts represent verifiable audit logs, while AI Copilot notes are designated non-authoritative."
      />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-zinc-100 tracking-tight">
            SOC Incident & Forensics Reporting
          </h1>
          <p className="text-xs text-zinc-400">
            Reports include uploaded-file analysis, scan results, evidence, and whether containment is recorded. Live telemetry is not connected.
          </p>
        </div>

        <button
          onClick={() => setIsCreatingReport(true)}
          className="inline-flex items-center gap-1.5 px-4 py-2 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold tracking-wide transition-colors shadow-xs self-start sm:self-auto"
        >
          <Plus className="w-4 h-4" />
          <span>Draft New Incident Report</span>
        </button>
      </div>

      {/* Main 2-column view: Report Index on left, Report Details on right */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Reports Index */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-4 shadow-xs space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
              Generated Reports ({reports.length})
            </h2>
            <span className="text-[11px] font-mono text-zinc-400">SOC ARCHIVE</span>
          </div>

          <div className="space-y-2 max-h-[600px] overflow-y-auto">
            {reports.map((rep) => {
              const isSelected = selectedReport?.id === rep.id;
              return (
                <button
                  key={rep.id}
                  onClick={() => setSelectedReport(rep)}
                  className={`w-full text-left p-3 rounded-lg border transition-all text-xs ${
                    isSelected
                      ? 'bg-zinc-800 text-zinc-100 border-cyan-600/80 shadow-xs'
                      : 'bg-zinc-950/70 text-zinc-300 border-zinc-800 hover:bg-zinc-850'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-[10px] font-bold text-cyan-400 uppercase">
                      {rep.id}
                    </span>
                    <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-zinc-900 text-amber-300 border border-zinc-700">
                      {rep.classification}
                    </span>
                  </div>
                  <h3 className="font-semibold text-zinc-200 line-clamp-1">{rep.title}</h3>
                  <div className="mt-2 flex items-center justify-between text-[11px] font-mono text-zinc-400">
                    <span>{new Date(rep.createdAt).toLocaleDateString()}</span>
                    <span>{rep.evidenceItems.length} Evidence Logs</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Selected Report Preview */}
        <div className="lg:col-span-2 bg-zinc-900/90 border border-zinc-800 rounded-lg p-6 shadow-xs space-y-6">
          {selectedReport ? (
            <>
              {/* Report Header Actions */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 pb-4 border-b border-zinc-800">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {selectedReport.id}
                    </span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/60 text-amber-300 border border-amber-800/60">
                      {selectedReport.classification}
                    </span>
                    <span className="text-[11px] font-mono text-zinc-400 uppercase">
                      {selectedReport.type.replace('_', ' ')}
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-zinc-100">{selectedReport.title}</h2>
                  <p className="text-[11px] font-mono text-zinc-400">
                    Compiled: {new Date(selectedReport.createdAt).toUTCString()} • Author:{' '}
                    {selectedReport.author}
                  </p>
                </div>

                <div className="flex items-center gap-2 self-start sm:self-auto">
                  <button
                    onClick={handleCopyMarkdown}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium transition-colors"
                  >
                    {copiedSuccess ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSuccess ? 'Copied Markdown' : 'Copy MD'}</span>
                  </button>

                  <button
                    onClick={handleDownloadJson}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>JSON</span>
                  </button>
                </div>
              </div>

              {/* 1. Executive Summary */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                  1. Executive Summary & Analyst Conclusions
                </h3>
                <p className="text-xs text-zinc-200 leading-relaxed bg-zinc-950 p-4 rounded-lg border border-zinc-800/80">
                  {selectedReport.analystConclusions}
                </p>
              </div>

              {/* 2. Deterministic Telemetry & Evidence (Clearly distinct) */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-emerald-400" />
                    2. Verifiable Evidence Artifacts (Deterministic Telemetry)
                  </h3>
                  <span className="text-[10px] font-mono text-zinc-400">
                    {selectedReport.evidenceItems.length} Artifacts Attached
                  </span>
                </div>

                {selectedReport.evidenceItems.length === 0 ? (
                  <div className="p-4 bg-zinc-950 border border-zinc-800 rounded-lg text-xs text-zinc-500">
                    No individual evidence logs linked.
                  </div>
                ) : (
                  <div className="border border-zinc-800 rounded-lg divide-y divide-zinc-800/80 overflow-hidden bg-zinc-950">
                    {selectedReport.evidenceItems.map((ev, i) => (
                      <div key={i} className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                        <div className="space-y-1">
                          <span className="text-[11px] font-mono text-cyan-400 font-semibold block">
                            {ev.source}
                          </span>
                          <span className="font-mono text-zinc-200">{ev.indicator}</span>
                        </div>
                        <div className="text-right sm:max-w-xs shrink-0 flex items-center gap-2 self-start sm:self-auto">
                          <SeverityBadge severity={ev.severity} size="sm" />
                          <span className="text-[10px] font-mono text-zinc-400 px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800">
                            {ev.verificationStatus}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 3. AI Copilot Non-authoritative Advisory (Strict boundary) */}
              <div className="space-y-2">
                <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-cyan-400">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>3. AI Security Copilot Advisory (Non-Authoritative)</span>
                </div>

                <div className="p-4 bg-cyan-950/20 border border-cyan-900/40 rounded-lg space-y-2 text-xs">
                  <div className="flex items-start gap-2 text-zinc-300">
                    <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                    <p className="text-[11px] text-cyan-200/90">
                      The recommendations below represent model-generated decision support. Analysts must confirm indicators against authoritative system logs prior to executing host quarantine or network blockades.
                    </p>
                  </div>

                  <ul className="list-disc pl-5 space-y-1.5 text-zinc-200 pt-2 border-t border-cyan-900/30">
                    {selectedReport.aiAssistanceNotes.map((note, idx) => (
                      <li key={idx}>{note}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* 4. Action Items */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                  4. Response Actions & Recorded Outcome
                </h3>
                <p className="text-[11px] text-amber-200">Update each action after responding in your security product. Status is manually recorded here and is not verified by the dashboard.</p>
                <div className="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-950">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-zinc-900 text-zinc-400 text-[11px] border-b border-zinc-800">
                      <tr>
                        <th className="py-2.5 px-3">Remediation Action</th>
                        <th className="py-2.5 px-3">Assigned to</th>
                        <th className="py-2.5 px-3">Target SLA</th>
                        <th className="py-2.5 px-3 text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800/80">
                      {selectedReport.actionItems.map((act, i) => (
                        <tr key={i} className="hover:bg-zinc-900/40">
                          <td className="py-2.5 px-3 font-sans text-zinc-200">{act.action}</td>
                          <td className="py-2.5 px-3 text-cyan-400">{act.assignedTo}</td>
                          <td className="py-2.5 px-3 text-zinc-400">
                            {new Date(act.dueDate).toLocaleTimeString()}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <select
                              value={act.status}
                              onChange={(event) => handleActionStatusChange(i, event.target.value as ReportItem['actionItems'][number]['status'])}
                              aria-label={`Record response status for ${act.action}`}
                              className={`px-1.5 py-1 rounded text-[10px] bg-zinc-900 border border-zinc-700 uppercase ${act.status === 'completed' ? 'text-emerald-400' : act.status === 'not_performed' ? 'text-amber-300' : 'text-zinc-300'}`}
                            >
                              <option value="not_performed">Not performed</option>
                              <option value="pending">Pending</option>
                              <option value="in_progress">In progress</option>
                              <option value="completed">Completed</option>
                            </select>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-zinc-500 text-xs">
              No report selected. Choose a report from the archive or draft a new one.
            </div>
          )}
        </div>
      </div>

      {/* Modal: Draft New Incident Report */}
      {isCreatingReport && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs overflow-y-auto"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-2xl bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl p-6 space-y-5 my-auto">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <h2 className="text-sm font-bold text-zinc-100 uppercase tracking-wider">
                Compile New Incident Report
              </h2>
              <button
                onClick={() => setIsCreatingReport(false)}
                className="text-zinc-400 hover:text-zinc-200 text-xs font-mono"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleGenerateReport} className="space-y-4 text-xs">
              <div className="space-y-1">
                <label className="font-semibold text-zinc-300">Report Title</label>
                <input
                  type="text"
                  required
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  placeholder="e.g. Cobalt Strike Lateral Movement Incident Brief"
                  className="w-full bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="font-semibold text-zinc-300">Report Classification</label>
                  <select
                    value={reportClassification}
                    onChange={(e) => setReportClassification(e.target.value as any)}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="TLP:AMBER">TLP:AMBER (Restricted)</option>
                    <option value="TLP:RED">TLP:RED (Strict Need-to-Know)</option>
                    <option value="TLP:GREEN">TLP:GREEN (Community)</option>
                    <option value="TLP:CLEAR">TLP:CLEAR (Public)</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="font-semibold text-zinc-300">Report Type</label>
                  <select
                    value={reportType}
                    onChange={(e) => setReportType(e.target.value as any)}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="incident_triage">Incident Triage Brief</option>
                    <option value="executive_summary">Executive Summary</option>
                    <option value="forensic_analysis">Forensic Memory Analysis</option>
                    <option value="threat_brief">Threat Intel Advisory</option>
                  </select>
                </div>
              </div>

              {/* Attach Alerts */}
              <div className="space-y-1">
                <label className="font-semibold text-zinc-300 block">
                  Select Evidence Alerts to Attach
                </label>
                <div className="max-h-36 overflow-y-auto space-y-1 p-2 bg-zinc-900/60 rounded border border-zinc-800">
                  {alerts.map((alert) => (
                    <label key={alert.id} className="flex items-center gap-2 p-1.5 hover:bg-zinc-800 rounded cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedAlertIds.includes(alert.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedAlertIds((prev) => [...prev, alert.id]);
                          } else {
                            setSelectedAlertIds((prev) => prev.filter((id) => id !== alert.id));
                          }
                        }}
                        className="rounded border-zinc-700 bg-zinc-950 text-cyan-600 focus:ring-cyan-500"
                      />
                      <span className="font-mono text-[11px] text-cyan-400">{alert.id}</span>
                      <span className="text-zinc-200 truncate">{alert.title}</span>
                    </label>
                  ))}
                </div>
              </div>

              {/* Attach Scans */}
              <div className="space-y-1">
                <label className="font-semibold text-zinc-300 block">
                  Select Scanner Findings to Attach
                </label>
                <div className="max-h-32 overflow-y-auto space-y-1 p-2 bg-zinc-900/60 rounded border border-zinc-800">
                  {scans.map((scan) => (
                    <label key={scan.id} className="flex items-center gap-2 p-1.5 hover:bg-zinc-800 rounded cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedScanIds.includes(scan.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setSelectedScanIds((prev) => [...prev, scan.id]);
                          } else {
                            setSelectedScanIds((prev) => prev.filter((id) => id !== scan.id));
                          }
                        }}
                        className="rounded border-zinc-700 bg-zinc-950 text-cyan-600 focus:ring-cyan-500"
                      />
                      <span className="font-mono text-[11px] text-zinc-400 uppercase">
                        [{scan.scannerType}]
                      </span>
                      <span className="text-zinc-200 truncate">{scan.input}</span>
                      <span className="font-mono text-amber-400 text-[10px]">
                        ({scan.riskScore}/100)
                      </span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <label className="font-semibold text-zinc-300">Analyst Conclusions</label>
                <textarea
                  rows={3}
                  value={analystNotes}
                  onChange={(e) => setAnalystNotes(e.target.value)}
                  placeholder="Record factual conclusions and current containment status..."
                  className="w-full bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-zinc-800">
                <button
                  type="button"
                  onClick={() => setIsCreatingReport(false)}
                  className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold"
                >
                  Generate Incident Report
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
