/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Server,
  Activity,
  Crosshair,
  TrendingUp,
  AlertTriangle,
  ArrowRight,
  Filter,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { DataCard } from '../components/common/DataCard';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { SeverityLevel } from '../types';

export const Overview: React.FC = () => {
  const { alerts, assets, scans, activityLogs, openAlertModal } = useSecurity();
  const navigate = useNavigate();
  const [timeRange, setTimeRange] = useState<'7d' | '30d' | '90d'>('30d');
  const [kevEntries, setKevEntries] = useState<Array<{ dateAdded: string; knownRansomwareCampaignUse?: string; vendorProject?: string }>>([]);
  const [kevLoading, setKevLoading] = useState(true);
  const [kevError, setKevError] = useState('');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<string>('all');

  useEffect(() => {
    let active = true;
    const loadCatalog = async () => {
      try {
        const response = await fetch('/api/threat-intel', { cache: 'no-store' });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Public catalog unavailable');
        if (active && Array.isArray(payload.vulnerabilities)) {
          setKevEntries(payload.vulnerabilities);
          setKevError('');
        }
      } catch (error) {
        if (active) setKevError(error instanceof Error ? error.message : 'Public catalog unavailable');
      } finally {
        if (active) setKevLoading(false);
      }
    };
    void loadCatalog();
    const timer = window.setInterval(() => void loadCatalog(), 15 * 60 * 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  // Key metrics
  const criticalCount = alerts.filter((a) => a.severity === 'critical' && a.status !== 'resolved').length;
  const highCount = alerts.filter((a) => a.severity === 'high' && a.status !== 'resolved').length;
  const openIncidents = alerts.filter((a) => a.status === 'new' || a.status === 'investigating').length;
  const compromisedAssets = assets.filter((a) => a.status === 'compromised' || a.status === 'quarantined').length;
  const avgRiskScore = scans.length > 0
    ? Math.round(scans.reduce((acc, s) => acc + s.riskScore, 0) / scans.length)
    : 0;

  // Filtered alerts
  const filteredAlerts = alerts.filter((alert) => {
    if (selectedSeverityFilter === 'all') return true;
    return alert.severity === selectedSeverityFilter;
  });

  // CISA publishes calendar dates, not event timestamps; this charts catalog
  // additions by day and never presents them as attacks against this user.
  const days = timeRange === '7d' ? 7 : timeRange === '30d' ? 30 : 90;
  const today = new Date();
  const timeSeriesPoints = Array.from({ length: days }, (_, index) => {
    const day = new Date(today);
    day.setHours(0, 0, 0, 0);
    day.setDate(day.getDate() - (days - index - 1));
    const key = `${day.getFullYear()}-${String(day.getMonth() + 1).padStart(2, '0')}-${String(day.getDate()).padStart(2, '0')}`;
    return {
      label: days === 7 ? day.toLocaleDateString(undefined, { weekday: 'short' }) : day.toLocaleDateString(undefined, { month: 'numeric', day: 'numeric' }),
      count: kevEntries.filter((entry) => entry.dateAdded === key).length,
    };
  });
  const maxVal = Math.max(...timeSeriesPoints.map((point) => point.count), 1);
  const catalogTotal = kevEntries.length;
  const catalogRecent = kevEntries.filter((entry) => {
    const age = today.getTime() - new Date(`${entry.dateAdded}T00:00:00`).getTime();
    return age >= 0 && age < 7 * 24 * 60 * 60 * 1000;
  }).length;
  const ransomwareEntries = kevEntries.filter((entry) => entry.knownRansomwareCampaignUse?.toLowerCase() === 'known').length;
  const latestCatalogDate = kevEntries.map((entry) => entry.dateAdded).sort().at(-1) || null;

  // Severity category distribution
  const severityCounts: Record<SeverityLevel, number> = {
    critical: alerts.filter((a) => a.severity === 'critical').length,
    high: alerts.filter((a) => a.severity === 'high').length,
    medium: alerts.filter((a) => a.severity === 'medium').length,
    low: alerts.filter((a) => a.severity === 'low').length,
    info: alerts.filter((a) => a.severity === 'info').length,
  };

  return (
    <div className="space-y-6">
      {/* Top Banner Notice */}
      <NoticeBanner
        type="demo"
        customMessage="Sample dashboard records are shown for demonstration. They are not live device or network telemetry."
      />

      {/* Metric Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <DataCard
          title="Active Critical Threats"
          value={criticalCount}
          subtitle="Sample records; verify in a connected security tool"
          accentColor="red"
          icon={<ShieldAlert className="w-5 h-5 text-red-400" />}
          trend={{ direction: 'neutral', text: 'Sample data', isPositive: true }}
          onClick={() => {
            setSelectedSeverityFilter('critical');
          }}
        />

        <DataCard
          title="Open Incidents"
          value={openIncidents}
          subtitle={`${alerts.length} sample and session records`}
          accentColor="amber"
          icon={<Activity className="w-5 h-5 text-amber-400" />}
          trend={{ direction: 'neutral', text: 'No live feed', isPositive: true }}
          onClick={() => navigate('/alerts')}
        />

        <DataCard
          title="Compromised Assets"
          value={compromisedAssets}
          subtitle="No device integration connected"
          accentColor="blue"
          icon={<Server className="w-5 h-5 text-blue-400" />}
          trend={{ direction: 'neutral', text: 'No live source', isPositive: true }}
          onClick={() => navigate('/assets')}
        />

        <DataCard
          title="Avg Threat Risk Score"
          value={`${avgRiskScore}/100`}
          subtitle="Calculated via explainable heuristics"
          accentColor={avgRiskScore >= 70 ? 'red' : 'amber'}
          icon={<Crosshair className="w-5 h-5 text-cyan-400" />}
          trend={{ direction: 'neutral', text: scans.length ? 'Sample scan data' : 'No scan data', isPositive: true }}
          onClick={() => navigate('/scanners')}
        />
      </div>

      {/* Main Charts & Distribution Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Time-series Threat Chart (2 cols) */}
        <div className="lg:col-span-2 bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
            <div>
              <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider">
                Public Catalog Additions
              </h2>
              <p className="text-xs text-zinc-400">
                CISA known-exploited vulnerability entries by date added. This is not activity on your network.
              </p>
            </div>

            {/* Time range picker */}
            <div className="inline-flex rounded-md bg-zinc-950 p-1 border border-zinc-800 self-start sm:self-auto">
              {(['7d', '30d', '90d'] as const).map((range) => (
                <button
                  key={range}
                  onClick={() => setTimeRange(range)}
                  className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                    timeRange === range
                      ? 'bg-zinc-800 text-cyan-400 font-semibold shadow-xs'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  {range.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Accessible, clean SVG Bar / Line Representation */}
          <div className="h-64 w-full flex items-end gap-3 sm:gap-6 pt-6 pb-2 px-2 border-b border-zinc-800">
            {timeSeriesPoints.map((pt, i) => {
              const height = (pt.count / maxVal) * 100;
              return (
                <div key={i} className="flex-1 flex flex-col items-center h-full justify-end group">
                  <div className="w-full max-w-[36px] rounded-t overflow-hidden bg-zinc-800/40 transition-all duration-300 group-hover:brightness-125" style={{ height: `${height}%`, minHeight: pt.count > 0 ? '3px' : '0' }} title={`${pt.label}: ${pt.count} catalog additions`}>
                    <div
                      className="w-full h-full bg-cyan-500/80"
                    />
                  </div>
                  <span className="mt-2 text-[11px] font-mono text-zinc-400 group-hover:text-zinc-200">
                    {pt.label}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Chart Legend */}
          <div className="flex flex-wrap items-center justify-between gap-3 mt-4 pt-2 text-xs">
            <span className="flex items-center gap-1.5 text-zinc-400"><span className="w-2.5 h-2.5 rounded-xs bg-cyan-500" /> CISA catalog entries</span>
            <span className="font-mono text-[11px] text-zinc-400">{kevLoading ? 'Loading public catalog…' : kevError ? 'Catalog unavailable' : `${catalogRecent} added in the last 7 days • ${catalogTotal} total`}</span>
          </div>
          {kevError && <div className="mt-2 text-[11px] text-amber-300">{kevError}</div>}
          {!kevLoading && !kevError && timeSeriesPoints.every((point) => point.count === 0) && <div className="mt-2 text-[11px] text-zinc-500">No catalog entries were added in this date range. This is a zero count, not missing activity data.</div>}
        </div>

        {/* Public catalog summary (1 col) */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider mb-1">
              Global Catalog Snapshot
            </h2>
            <p className="text-xs text-zinc-400 mb-4">
              Public CISA data; not device detections or severity ratings
            </p>

            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs"><span className="text-zinc-300">Catalog entries</span><strong className="font-mono text-cyan-300">{kevLoading ? '…' : kevError ? 'Unavailable' : catalogTotal}</strong></div>
              <div className="flex items-center justify-between text-xs"><span className="text-zinc-300">Added in last 7 days</span><strong className="font-mono text-cyan-300">{kevLoading ? '…' : kevError ? '—' : catalogRecent}</strong></div>
              <div className="flex items-center justify-between text-xs"><span className="text-zinc-300">Known ransomware use</span><strong className="font-mono text-amber-300">{kevLoading ? '…' : kevError ? '—' : ransomwareEntries}</strong></div>
              <div className="flex items-center justify-between text-xs"><span className="text-zinc-300">Most recent catalog date</span><strong className="font-mono text-zinc-200">{latestCatalogDate || '—'}</strong></div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-zinc-800 text-xs">
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-zinc-400 mb-2">
              What this means
            </h3>
            <p className="text-zinc-400 leading-relaxed">CISA lists vulnerabilities exploited somewhere in the wild. This dashboard cannot tell whether your systems are affected.</p>
          </div>
        </div>
      </div>

      {/* Recent Alerts & Incident Queue */}
      <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider">
              Recent Alerts & Incidents
            </h2>
            <p className="text-xs text-zinc-400">
              Click any incident to inspect forensics timeline and launch containment actions
            </p>
          </div>

          {/* Quick Filter */}
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-zinc-500" />
            <select
              value={selectedSeverityFilter}
              onChange={(e) => setSelectedSeverityFilter(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 rounded px-2.5 py-1 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Severities ({alerts.length})</option>
              <option value="critical">Critical Only ({severityCounts.critical})</option>
              <option value="high">High Only ({severityCounts.high})</option>
              <option value="medium">Medium Only ({severityCounts.medium})</option>
              <option value="low">Low Only ({severityCounts.low})</option>
            </select>

            <button
              onClick={() => navigate('/alerts')}
              className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium rounded border border-zinc-700 transition-colors inline-flex items-center gap-1"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto border border-zinc-800 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-zinc-950 text-zinc-400 font-mono uppercase text-[11px] border-b border-zinc-800">
              <tr>
                <th className="py-2.5 px-4 font-medium">Severity</th>
                <th className="py-2.5 px-4 font-medium">Incident Title</th>
                <th className="py-2.5 px-4 font-medium">Affected Asset</th>
                <th className="py-2.5 px-4 font-medium">Detection Source</th>
                <th className="py-2.5 px-4 font-medium">Status</th>
                <th className="py-2.5 px-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/80 bg-zinc-900/40">
              {filteredAlerts.slice(0, 5).map((alert) => (
                <tr
                  key={alert.id}
                  className="hover:bg-zinc-800/50 transition-colors cursor-pointer group"
                  onClick={() => openAlertModal(alert)}
                >
                  <td className="py-3 px-4">
                    <SeverityBadge severity={alert.severity} size="sm" />
                  </td>
                  <td className="py-3 px-4 font-medium text-zinc-200">
                    <div className="font-semibold text-zinc-100 group-hover:text-cyan-400 transition-colors">
                      {alert.title}
                    </div>
                    <div className="text-[11px] font-mono text-zinc-400">
                      ID: {alert.id} • {alert.mitreTechnique || 'Unmapped'}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5 text-zinc-300 font-mono">
                      <Server className="w-3 h-3 text-cyan-400" />
                      <span>{alert.affectedAsset}</span>
                    </div>
                    <div className="text-[11px] font-mono text-zinc-400">{alert.assetIp}</div>
                  </td>
                  <td className="py-3 px-4 text-zinc-400 truncate max-w-xs">{alert.source}</td>
                  <td className="py-3 px-4">
                    <StatusBadge status={alert.status} />
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        openAlertModal(alert);
                      }}
                      className="px-2.5 py-1 rounded bg-zinc-800 group-hover:bg-cyan-950 group-hover:text-cyan-300 group-hover:border-cyan-700 text-zinc-300 border border-zinc-700 text-xs font-medium transition-colors"
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom 2-Column: Recent Scans & Activity Log */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans Panel */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider">
                Recent Scanner Artifacts
              </h2>
              <p className="text-xs text-zinc-400">
                Latest payload and network findings with explainable scoring
              </p>
            </div>
            <button
              onClick={() => navigate('/scanners')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono inline-flex items-center gap-1"
            >
              <span>Open Scanners</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {scans.slice(0, 3).map((scan) => (
              <div
                key={scan.id}
                className="p-3 rounded bg-zinc-950 border border-zinc-800/80 flex items-start justify-between gap-3 text-xs"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                      {scan.scannerType}
                    </span>
                    <SeverityBadge severity={scan.severity} size="sm" />
                    <span className="font-mono text-zinc-400 text-[11px]">
                      Risk: <strong className="text-zinc-200">{scan.riskScore}/100</strong>
                    </span>
                  </div>
                  <p className="font-mono text-zinc-200 truncate">{scan.input}</p>
                  <p className="text-zinc-400 text-[11px] truncate">{scan.summary}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Live Analyst Activity Log */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider">
                Local Activity Log
              </h2>
              <p className="text-xs text-zinc-400">Local activity log (demo activity is not live system telemetry)</p>
            </div>
            <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              LOCAL DEMO LOG
            </span>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {activityLogs.slice(0, 4).map((log) => (
              <div
                key={log.id}
                className="p-2.5 rounded bg-zinc-950 border border-zinc-800/80 flex items-start gap-2.5"
              >
                <span className="text-zinc-500 text-[11px] shrink-0">{log.timestamp}</span>
                <div className="min-w-0 flex-1">
                  <div className="text-zinc-300 font-medium truncate">{log.action}</div>
                  <div className="text-[11px] text-zinc-400">
                    By <span className="text-zinc-300">{log.analyst}</span> in{' '}
                    <span className="text-cyan-400">{log.module}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
