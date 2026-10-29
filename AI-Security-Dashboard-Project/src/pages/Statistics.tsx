import React from 'react';
import { Bot, Clock, FileSearch, ShieldAlert } from 'lucide-react';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { useSecurity } from '../context/SecurityContext';

export const Statistics: React.FC = () => {
  const { alerts, scans, uploadedFiles, activityLogs } = useSecurity();
  const cards = [
    { title: 'Alerts available to review', value: alerts.length, note: 'Includes sample records until live sources are connected', icon: ShieldAlert },
    { title: 'Files analyzed in this session', value: uploadedFiles.length, note: 'Local heuristic analysis; no cloud storage is configured', icon: FileSearch },
    { title: 'Scanner results', value: scans.length, note: 'Sample data or user-submitted scans', icon: Clock },
    { title: 'AI assistance', value: 'Ready', note: 'Copilot supports review; it does not monitor systems by itself', icon: Bot },
  ];
  return <div className="space-y-6">
    <NoticeBanner type="demo" customMessage="Human shift metrics are not shown because no analyst team or verified shift data is configured. AI assists with the data you provide; it does not generate real monitoring activity." />
    <div><h1 className="text-lg font-bold text-zinc-100">AI Analysis & Activity</h1><p className="text-xs text-zinc-400">A transparent view of findings provided to the dashboard and AI-assisted reviews performed here.</p></div>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">{cards.map(({title,value,note,icon:Icon})=><div key={title} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="flex justify-between items-center"><span className="text-xs text-zinc-400">{title}</span><Icon className="w-4 h-4 text-cyan-400"/></div><div className="text-2xl font-bold text-zinc-100 mt-2">{value}</div><p className="text-[11px] text-zinc-500 mt-2">{note}</p></div>)}</div>
    <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 space-y-3"><h2 className="text-sm font-semibold text-zinc-100">Analyst shift watch</h2><p className="text-xs text-zinc-300">No analyst team is configured, so there are no names, shifts, response times, or SLA scores to report. AI-generated triage can be recorded alongside each uploaded file or alert, but it is decision support and does not count as a human analyst performance metric.</p><p className="text-[11px] text-zinc-500">Activity entries available in this browser session: {activityLogs.length}. Entries are local dashboard actions, not events collected from your network.</p></div>
  </div>;
};
