import React from 'react';
import { Activity, FileSearch, Server, ShieldAlert } from 'lucide-react';
import { Link } from 'react-router-dom';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { useSecurity } from '../context/SecurityContext';

export const Analytics: React.FC = () => {
  const { alerts, assets, scans, uploadedFiles } = useSecurity();
  const severities = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const cards = [
    { label: 'Alerts available', value: alerts.length, icon: ShieldAlert },
    { label: 'Connected devices', value: assets.length, icon: Server },
    { label: 'Scans in session', value: scans.length, icon: Activity },
    { label: 'Uploaded files analyzed', value: uploadedFiles.length, icon: FileSearch },
  ];
  return <div className="space-y-6">
    <NoticeBanner type="demo" customMessage="This page summarizes records in the dashboard. Seeded alerts and scanner results are sample data; no network telemetry or device protection feed is connected." />
    <div><h1 className="text-lg font-bold text-zinc-100">Security Analytics</h1><p className="text-xs text-zinc-400">Counts reflect records currently available in this dashboard, not a live threat stream.</p></div>
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">{cards.map(({label,value,icon:Icon})=><div key={label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="flex items-center justify-between"><span className="text-xs text-zinc-400">{label}</span><Icon className="w-4 h-4 text-cyan-400"/></div><div className="text-2xl font-bold text-zinc-100 mt-3">{value}</div></div>)}</div>
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5"><h2 className="text-sm font-semibold text-zinc-100 mb-4">Current alert records by severity</h2><div className="space-y-3">{severities.map(level=>{const n=alerts.filter(a=>a.severity===level).length; const width=alerts.length?Math.round(n/alerts.length*100):0; return <div key={level}><div className="flex justify-between text-xs mb-1"><span className="text-zinc-300 capitalize">{level}</span><span className="text-zinc-400">{n} ({width}%)</span></div><div className="h-2 bg-zinc-800 rounded overflow-hidden"><div style={{width:`${width}%`}} className={`h-full ${level==='critical'?'bg-red-500':level==='high'?'bg-rose-500':level==='medium'?'bg-amber-500':level==='low'?'bg-blue-500':'bg-emerald-500'}`}/></div></div>})}</div>{!alerts.length&&<p className="text-xs text-zinc-500 mt-3">No alert records yet. Connect a source to populate this view.</p>}</div>
    <div className="bg-amber-950/20 border border-amber-900/50 rounded-lg p-5"><h2 className="text-sm font-semibold text-amber-200">Live monitoring setup required</h2><p className="text-xs text-zinc-300 mt-2">To display live events, protected devices, and verified response outcomes, connect a SIEM/EDR/firewall source to a persistent backend. This frontend deployment cannot collect data from your devices by itself.</p><div className="flex gap-4 mt-4 text-xs"><Link className="text-cyan-300 hover:underline" to="/scanners">Open scanners</Link><Link className="text-cyan-300 hover:underline" to="/reports">Open reports</Link></div></div>
  </div>;
};
